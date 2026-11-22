import express from "express";
import { MongoClient, ObjectId } from 'mongodb';
import cors from "cors";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
// import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";
import "dotenv/config";

const PORT = process.env.PORT || 5000;
const app = express();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uploadsRoot = path.join(__dirname, "uploads");
const serviceUploadsDir = path.join(uploadsRoot, "services");

// fs.mkdirSync(serviceUploadsDir, { recursive: true });
// app.use(cors())
// Middleware
app.use(cors({
  origin: process.env.BETTER_AUTH_URL || 'http://localhost:3000', 
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
}));
app.use(express.json());
app.use("/uploads", express.static(uploadsRoot, { maxAge: "7d" }));

const authBaseURL = (
  process.env.BETTER_AUTH_URL || "http://localhost:3000"
).replace(/\/$/, "");
const authOrigin = new URL(authBaseURL).origin;
const authPath = authBaseURL.endsWith("/api/auth")
  ? authBaseURL
  : `${authBaseURL}/api/auth`;
const jwks = createRemoteJWKSet(new URL(`${authPath}/jwks`));


const jwtIssuer = process.env.JWT_ISSUER || authOrigin;
const jwtAudience = process.env.JWT_AUDIENCE || authOrigin;


const PROTECTED_ROUTE_PREFIXES = [
  "/admin",
  "/customer",
  "/profile",
  "/bookings",
];

const isProtectedRoute = (req) => {
  if (req.method === "OPTIONS") return false;

  const pathname = (req.path || "/").replace(/\/+$/, "") || "/";

  return PROTECTED_ROUTE_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );
};

const getBearerToken = (req) => {
  const header = req.headers.authorization;

  if (typeof header !== "string") return null;

  const [scheme, ...rest] = header.trim().split(/\s+/);

  if (!/^Bearer$/i.test(scheme)) return null;

  const token = rest.join("");

  return token || null;
};

const sendAuthError = (res, status, code, message) => {
  if (status === 401) {
    res.set("WWW-Authenticate", "Bearer");
  }

  return res.status(status).send({
    success: false,
    code,
    message,
  });
};


const getUserFromSessionCookie = async (cookie) => {
  try {
    const sessionResponse = await fetch(`${authPath}/get-session`, {
      headers: { cookie },
    });

    if (!sessionResponse.ok) return null;

    const sessionData = await sessionResponse.json();

    return sessionData?.user ?? sessionData?.data?.user ?? null;
  } catch (error) {
    console.error("Session lookup failed:", error.message);
    return null;
  }
};


const authenticateRequest = async (req, res, next) => {
  if (req.method === "OPTIONS") {
    return next();
  }

  const protectedRoute = isProtectedRoute(req);
  const token = getBearerToken(req);

  if (token) {
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: jwtIssuer,
        audience: jwtAudience,
      });

      req.user = payload;
      req.authSource = "jwt";
      return next();
    } catch (error) {
      const expired = error?.code === "ERR_JWT_EXPIRED";

      console.error(
        "JWT verification failed:",
        error?.code || error?.message || error
      );

      // Only fall through to the cookie session when the client actually sent
      // one. Otherwise a protected request fails immediately.
      if (!protectedRoute && !req.headers.cookie) {
        return next();
      }

      if (protectedRoute && !req.headers.cookie) {
        return sendAuthError(
          res,
          401,
          expired ? "TOKEN_EXPIRED" : "INVALID_TOKEN",
          expired
            ? "Your session has expired. Please sign in again."
            : "Invalid or expired authentication token."
        );
      }
    }
  }

  if (req.headers.cookie) {
    const user = await getUserFromSessionCookie(req.headers.cookie);

    if (user) {
      req.user = user;
      req.authSource = "session";
      return next();
    }

    if (protectedRoute) {
      return sendAuthError(
        res,
        401,
        "UNAUTHORIZED",
        "Your session has expired. Please sign in again."
      );
    }
  }

  if (protectedRoute) {
    return sendAuthError(
      res,
      401,
      "UNAUTHORIZED",
      "Authentication required. Please sign in."
    );
  }

  return next();
};

app.use(authenticateRequest);

// Test route
const upload = multer({
  storage: multer.memoryStorage(),
});

const profileUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(
        new Error("Profile image must be a JPG, PNG, WEBP or GIF file.")
      );
    }

    cb(null, true);
  },
});



const verifyCustomer = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized access",
    });
  }

  let role = req.user.role;
  let isBlocked =
    req.user.isBlocked === true || req.user.blocked === true;

  // The JWT payload may not carry role/isBlocked, so confirm with the database.
  if (req.user.email) {
    try {
      const user = await usersCollection.findOne(
        { email: req.user.email },
        { projection: { role: 1, blocked: 1, isBlocked: 1 } }
      );

      if (user) {
        role = user.role || role;
        isBlocked = user.blocked === true || user.isBlocked === true;
      }
    } catch (error) {
      console.error("Customer role lookup failed:", error);
      return res.status(500).send({
        success: false,
        message: "Failed to verify customer access",
      });
    }
  }

  if (role !== "customer") {
    return res.status(403).send({
      success: false,
      message: "Only customers can access this resource",
    });
  }

  if (isBlocked) {
    return res.status(403).send({
      success: false,
      message: "Your account has been blocked",
    });
  }

  req.user.role = role;
  next();
};

// verifyAdmin
const verifyAdmin = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized access",
    });
  }

  let role = req.user.role;
  let isBlocked =
    req.user.isBlocked === true || req.user.blocked === true;

  // The JWT payload may not carry role/isBlocked, so confirm with the database.
  if (req.user.email) {
    try {
      const user = await usersCollection.findOne(
        { email: req.user.email },
        { projection: { role: 1, isBlocked: 1, blocked: 1 } }
      );

      if (user) {
        role = user.role;
        isBlocked = user.blocked === true || user.isBlocked === true;
      }
    } catch (error) {
      console.error("Admin role lookup failed:", error);
      return res.status(500).send({
        success: false,
        message: "Failed to verify admin access",
      });
    }
  }

  if (role !== "admin") {
    return res.status(403).send({
      success: false,
      message: "Only admins can access this resource",
    });
  }

  if (isBlocked) {
    return res.status(403).send({
      success: false,
      message: "Your account has been blocked",
    });
  }

  req.user.role = role;
  next();
};

// verifyUser
// Allows any authenticated account (customer or admin) to manage its own
// profile. Blocked accounts are rejected inside the route after the database
// record has been checked.
const verifyUser = (req, res, next) => {
  if (!req.user) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized access",
    });
  }

  next();
};

const PROFILE_FORBIDDEN_FIELDS = new Set([
  "role",
  "blocked",
  "isBlocked",
  "email",
  "emailVerified",
  "_id",
  "id",
  "userId",
  "createdAt",
  "updatedAt",
]);

const isAccountBlocked = (user) =>
  user?.blocked === true || user?.isBlocked === true;

const sanitizeProfileUser = (user) => ({
  _id: user._id,
  name: user.name || "",
  email: user.email || "",
  image: user.image || "",
  phone: user.phone || "",
  address: user.address || "",
  role: user.role || "customer",
  blocked: isAccountBlocked(user),
  createdAt: user.createdAt,
});

const validateProfilePayload = (body) => {
  const input = body && typeof body === "object" ? body : {};
  const errors = [];
  const data = {};

  const forbiddenFields = Object.keys(input).filter((field) =>
    PROFILE_FORBIDDEN_FIELDS.has(field)
  );

  if (forbiddenFields.length > 0) {
    return {
      data,
      errors: [
        `You are not allowed to update: ${forbiddenFields.join(", ")}.`,
      ],
    };
  }

  const name = typeof input.name === "string" ? input.name.trim() : "";

  if (!name) {
    errors.push("Name is required.");
  } else if (name.length < 2 || name.length > 80) {
    errors.push("Name must be between 2 and 80 characters.");
  } else {
    data.name = name;
  }

  if (Object.prototype.hasOwnProperty.call(input, "phone")) {
    if (input.phone !== null && typeof input.phone !== "string") {
      errors.push("Phone must be text.");
    } else {
      const phone =
        typeof input.phone === "string" ? input.phone.trim() : "";

      if (phone.length > 20) {
        errors.push("Phone cannot exceed 20 characters.");
      } else if (phone && phone.length < 7) {
        errors.push("Phone must be at least 7 characters.");
      } else if (phone && !/^[0-9+\-\s()]+$/.test(phone)) {
        errors.push("Phone contains invalid characters.");
      } else {
        data.phone = phone;
      }
    }
  }

  if (Object.prototype.hasOwnProperty.call(input, "address")) {
    if (input.address !== null && typeof input.address !== "string") {
      errors.push("Address must be text.");
    } else {
      const address =
        typeof input.address === "string" ? input.address.trim() : "";

      if (address.length > 200) {
        errors.push("Address cannot exceed 200 characters.");
      } else {
        data.address = address;
      }
    }
  }

  if (Object.prototype.hasOwnProperty.call(input, "image")) {
    if (input.image !== null && typeof input.image !== "string") {
      errors.push("Profile image must be a URL.");
    } else {
      const image =
        typeof input.image === "string" ? input.image.trim() : "";

      if (image.length > 2048) {
        errors.push("Profile image URL is too long.");
      } else if (image) {
        try {
          const url = new URL(image);

          if (!["http:", "https:"].includes(url.protocol)) {
            throw new Error("Invalid protocol");
          }

          data.image = image;
        } catch {
          errors.push("Profile image must be a valid http or https URL.");
        }
      } else {
        data.image = "";
      }
    }
  }

  return { data, errors };
};

// ==================================
// Profile: shared by customers and admins
// ==================================

app.get("/profile", verifyUser, async (req, res) => {
  try {
    const user = await usersCollection.findOne({
      email: req.user.email,
    });

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "User not found",
      });
    }

    if (isAccountBlocked(user)) {
      return res.status(403).send({
        success: false,
        message: "Your account has been blocked",
      });
    }

    res.send({
      success: true,
      user: sanitizeProfileUser(user),
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch profile",
    });
  }
});

app.patch("/profile", verifyUser, async (req, res) => {
  try {
    const user = await usersCollection.findOne({
      email: req.user.email,
    });

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "User not found",
      });
    }

    if (isAccountBlocked(user)) {
      return res.status(403).send({
        success: false,
        message: "Your account has been blocked",
      });
    }

    const { data, errors } = validateProfilePayload(req.body);

    if (errors.length > 0) {
      return res.status(400).send({
        success: false,
        message: errors[0],
        errors,
      });
    }

    // The update always targets the authenticated user's own record. Role,
    // blocked status, email and identifiers are rejected above.
    await usersCollection.updateOne(
      { email: req.user.email },
      {
        $set: {
          ...data,
          updatedAt: new Date(),
        },
      }
    );

    const updated = await usersCollection.findOne({
      email: req.user.email,
    });

    res.send({
      success: true,
      message: "Profile updated successfully",
      user: sanitizeProfileUser(updated),
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to update profile",
    });
  }
});

app.post(
  "/profile/image",
  verifyUser,
  (req, res, next) => {
    profileUpload.single("image")(req, res, (error) => {
      if (error) {
        return res.status(400).send({
          success: false,
          message: error.message || "Profile image upload failed",
        });
      }

      next();
    });
  },
  async (req, res) => {
    try {
      const user = await usersCollection.findOne({
        email: req.user.email,
      });

      if (!user) {
        return res.status(404).send({
          success: false,
          message: "User not found",
        });
      }

      if (isAccountBlocked(user)) {
        return res.status(403).send({
          success: false,
          message: "Your account has been blocked",
        });
      }

      if (!req.file) {
        return res.status(400).send({
          success: false,
          message: "Profile image is required",
        });
      }

      const image = await uploadToImgBB(req.file);

      await usersCollection.updateOne(
        { email: req.user.email },
        {
          $set: {
            image,
            updatedAt: new Date(),
          },
        }
      );

      res.send({
        success: true,
        message: "Profile image updated successfully",
        image,
      });
    } catch (error) {
      console.error("Profile image upload error:", error);
      res.status(500).send({
        success: false,
        message: error.message || "Failed to upload profile image",
      });
    }
  }
);

// UI api Call
app.get("/", (req, res) => {
  res.send("SalonBook Server is Running!");
});

const client = new MongoClient(process.env.MONGODB_URL);
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}

const Connection = await connectToMongoDB();
const database = Connection.db("SalonBook");
const servicesCollection = database.collection('services')
const appointmentsCollection = database.collection("appointments");
const usersCollection = database.collection("user");
const transactionsCollection = database.collection("transactions");

const SERVICE_STATUSES = new Set(["active", "inactive"]);

// ---------------------------------------------------------------------------
// Search / sorting helpers
// ---------------------------------------------------------------------------

// Accepted price sort values. Both kebab-case (used by the UI) and snake_case
// (common in APIs) are supported so clients can pick either convention.
const PRICE_ASC_SORTS = new Set([
  "price-asc",
  "price_asc",
  "priceasc",
  "low-to-high",
  "lowtohigh",
  "price-low-to-high",
  "asc",
  "ascending",
]);

const PRICE_DESC_SORTS = new Set([
  "price-desc",
  "price_desc",
  "pricedesc",
  "high-to-low",
  "hightolow",
  "price-high-to-low",
  "desc",
  "descending",
]);

const SERVICE_SORT_OPTIONS = {
  default: { createdAt: -1, _id: -1 },
  newest: { createdAt: -1, _id: -1 },
  oldest: { createdAt: 1, _id: 1 },
  "price-asc": { price: 1, serviceName: 1 },
  "price-desc": { price: -1, serviceName: 1 },
  "name-asc": { serviceName: 1 },
  "name-desc": { serviceName: -1 },
};

const APPOINTMENT_SORT_OPTIONS = {
  default: { createdAt: -1, _id: -1 },
  newest: { createdAt: -1, _id: -1 },
  oldest: { createdAt: 1, _id: 1 },
  "price-asc": { price: 1, createdAt: -1 },
  "price-desc": { price: -1, createdAt: -1 },
  "date-asc": { appointmentDate: 1, appointmentTime: 1 },
  "date-desc": { appointmentDate: -1, appointmentTime: -1 },
};

const TRANSACTION_SORT_OPTIONS = {
  default: { transactionDate: -1, _id: -1 },
  newest: { transactionDate: -1, _id: -1 },
  oldest: { transactionDate: 1, _id: 1 },
  "price-asc": { paymentAmount: 1, transactionDate: -1 },
  "price-desc": { paymentAmount: -1, transactionDate: -1 },
};

const escapeRegex = (value) =>
  String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const getSearchTerm = (query = {}) => {
  const raw = query.search ?? query.q ?? query.serviceName ?? "";

  if (typeof raw !== "string") return "";

  // Keep the regex bounded so a huge value cannot slow the query down.
  return raw.trim().slice(0, 100);
};

// Translate ?sort=price-asc / ?sort=low-to-high / ?sortBy=price&order=desc
// into a MongoDB sort document.
const normalizeSort = (query = {}, options, fallback = "default") => {
  const rawSort = String(query.sort ?? query.sortBy ?? "")
    .trim()
    .toLowerCase();
  const rawOrder = String(query.order ?? query.sortOrder ?? "")
    .trim()
    .toLowerCase();

  if (!rawSort) return options[fallback];

  if (options[rawSort]) return options[rawSort];

  if (PRICE_ASC_SORTS.has(rawSort)) {
    return options["price-asc"] ?? options[fallback];
  }

  if (PRICE_DESC_SORTS.has(rawSort)) {
    return options["price-desc"] ?? options[fallback];
  }

  if (rawSort === "price") {
    return ["desc", "descending", "high-to-low"].includes(rawOrder)
      ? options["price-desc"]
      : options["price-asc"];
  }

  if (rawSort === "name") {
    return rawOrder === "desc" ? options["name-desc"] : options["name-asc"];
  }

  return options[fallback];
};

// Build a Mongo filter that searches service names case-insensitively and
// optionally narrows by category.
const buildServiceFilter = (query = {}, base = {}) => {
  const filter = { ...base };
  const search = getSearchTerm(query);

  if (search) {
    filter.serviceName = { $regex: escapeRegex(search), $options: "i" };
  }

  if (
    typeof query.category === "string" &&
    query.category.trim() &&
    query.category.trim().toLowerCase() !== "all"
  ) {
    filter.category = {
      $regex: `^${escapeRegex(query.category.trim())}$`,
      $options: "i",
    };
  }

  return filter;
};

const buildAppointmentFilter = (query = {}, base = {}) => {
  const filter = { ...base };
  const search = getSearchTerm(query);

  if (search) {
    filter.serviceName = { $regex: escapeRegex(search), $options: "i" };
  }

  return filter;
};

// Transactions are searched by service name (with customer details as a
// convenience) so the admin transactions page can reuse the same ?search=.
const buildTransactionFilter = (query = {}, base = {}) => {
  const filter = { ...base };
  const search = getSearchTerm(query);

  if (search) {
    const matcher = { $regex: escapeRegex(search), $options: "i" };

    filter.$or = [
      { serviceName: matcher },
      { customerName: matcher },
      { customerEmail: matcher },
    ];
  }

  return filter;
};

const getServiceStatusFilter = (query = {}) => {
  const status =
    typeof query.status === "string" ? query.status.trim().toLowerCase() : "";

  return SERVICE_STATUSES.has(status) ? status : "";
};


const validateServicePayload = (body, { partial = false } = {}) => {
  const input = body && typeof body === "object" ? body : {};
  const has = (field) => Object.prototype.hasOwnProperty.call(input, field);
  const errors = [];
  const data = {};

  if (!partial || has("serviceName")) {
    const serviceName =
      typeof input.serviceName === "string" ? input.serviceName.trim() : "";

    if (!serviceName) {
      errors.push("Service name is required.");
    } else {
      data.serviceName = serviceName;
    }
  }

  if (!partial || has("category")) {
    const category =
      typeof input.category === "string" ? input.category.trim() : "";

    if (!category) {
      errors.push("Category is required.");
    } else {
      data.category = category;
    }
  }

  if (has("description")) {
    if (typeof input.description !== "string") {
      errors.push("Description must be text.");
    } else {
      data.description = input.description.trim();
    }
  } else if (!partial) {
    data.description = "";
  }

  if (!partial || has("price")) {
    const price =
      typeof input.price === "number" ? input.price : Number(input.price);

    if (!Number.isFinite(price) || price < 0) {
      errors.push("Price must be a number greater than or equal to 0.");
    } else {
      data.price = price;
    }
  }

  if (!partial || has("duration")) {
    const duration =
      typeof input.duration === "number"
        ? input.duration
        : Number(input.duration);

    if (!Number.isFinite(duration) || duration <= 0) {
      errors.push("Duration must be a number greater than 0.");
    } else {
      data.duration = duration;
    }
  }

  if (has("image")) {
    if (typeof input.image !== "string") {
      errors.push("Image must be a URL.");
    } else {
      data.image = input.image.trim();
    }
  } else if (!partial) {
    data.image = "";
  }

  if (has("status")) {
    const status =
      typeof input.status === "string" ? input.status.toLowerCase() : "";

    if (!SERVICE_STATUSES.has(status)) {
      errors.push("Status must be either active or inactive.");
    } else {
      data.status = status;
    }
  } else if (!partial) {
    data.status = "active";
  }

  return { data, errors };
};


// services/Featured
// Supports the same ?search= and ?sort= query parameters as /services.
app.get("/services/Featured", async (req, res) => {
  try {
    const filter = buildServiceFilter(req.query, { status: "active" });

    const result = await servicesCollection
      .find(filter)
      .sort(normalizeSort(req.query, SERVICE_SORT_OPTIONS))
      .limit(6)
      .toArray();

    res.send(result);
  } catch (error) {
    console.error("Featured services fetch error:", error);
    res.status(500).send({
      message: "Failed to fetch featured services",
    });
  }
});

// Services
// Examples:
//   /services?search=hair
//   /services?sort=price-asc
//   /services?sort=price-desc&category=Hair%20Care
app.get("/services", async (req, res) => {
  try {
    const filter = buildServiceFilter(req.query, { status: "active" });

    const result = await servicesCollection
      .find(filter)
      .sort(normalizeSort(req.query, SERVICE_SORT_OPTIONS))
      .toArray();

    res.send(result);
  } catch (error) {
    console.error("Services fetch error:", error);
    res.status(500).send({
      message: "Failed to fetch services",
    });
  }
});
// Service Details Page Dynamic route 

app.get("/services/:id", async (req, res) => {
  const { id } = req.params;
  try {
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid service ID",
      });
    }
    // Inactive services are not visible on the public site.
    const service = await servicesCollection.findOne({
      _id: new ObjectId(id),
      status: "active",
    });
    if (!service) {
      return res.status(404).send({
        message: "Service not found",
      });
    }
    res.send(service);
  } catch (error) {
    res.status(500).send({
      message: "Failed to fetch service",
    });
  }
});

// booking services


app.post("/bookings", verifyCustomer, async (req, res) => {
  try {
    const {
      serviceId,
      appointmentDate,
      appointmentTime,
      customerMessage,
    } = req.body;

    // 1. Validate service ID
    if (!serviceId || !ObjectId.isValid(serviceId)) {
      return res.status(400).send({
        success: false,
        message: "Invalid service ID",
      });
    }

    // 2. Validate required fields
    if (!appointmentDate || !appointmentTime) {
      return res.status(400).send({
        success: false,
        message: "Appointment date and time are required",
      });
    }

    // 3. Validate date format
    if (
      typeof appointmentDate !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(appointmentDate)
    ) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment date",
      });
    }

    // 4. Validate actual calendar date
    const [year, month, day] = appointmentDate
      .split("-")
      .map(Number);

    const selectedDate = new Date(
      Date.UTC(year, month - 1, day)
    );

    if (
      selectedDate.getUTCFullYear() !== year ||
      selectedDate.getUTCMonth() !== month - 1 ||
      selectedDate.getUTCDate() !== day
    ) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment date",
      });
    }

    // 5. Get today's date in Bangladesh timezone
    const today = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Dhaka",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date());

    // 6. Prevent past date booking
    if (appointmentDate < today) {
      return res.status(400).send({
        success: false,
        message: "Please select today or a future date",
      });
    }

    // 7. Validate appointment time
    const allowedTimes = [
      "10:00 AM",
      "11:00 AM",
      "12:00 PM",
      "01:00 PM",
      "02:00 PM",
      "03:00 PM",
      "04:00 PM",
      "05:00 PM",
    ];

    if (!allowedTimes.includes(appointmentTime)) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment time",
      });
    }

    // 8. Validate customer message
    if (
      typeof customerMessage === "string" &&
      customerMessage.length > 500
    ) {
      return res.status(400).send({
        success: false,
        message: "Message cannot exceed 500 characters",
      });
    }

    // 9. Find active service
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
      status: "active",
    });

    if (!service) {
      return res.status(404).send({
        success: false,
        message: "Service not found or unavailable",
      });
    }

    // 10. Find customer
    const user = await usersCollection.findOne({
      email: req.user.email,
    });

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Customer not found",
      });
    }

    // 11. Prevent duplicate active bookings
    const existingBooking = await appointmentsCollection.findOne({
        serviceId: service._id,
      appointmentDate,
      appointmentTime,
      status: {
        $in: ["Pending", "Confirmed"],
      },
    });

    if (existingBooking) {
      return res.status(409).send({
        success: false,
        message: "This appointment slot is already booked",
      });
    }

    // 12. Create appointment
    const now = new Date();

    const newBooking = {
      customerName: user.name || "",
      customerEmail: user.email,
      serviceId: service._id,
      serviceName: service.serviceName,
      category: service.category,
      price: service.price,
      duration: service.duration,
      image: service.image,
      appointmentDate,
      appointmentTime,
      customerMessage:
        typeof customerMessage === "string"
          ? customerMessage.trim()
          : "",
      status: "Pending",
      paymentStatus: "Unpaid",
      createdAt: now,
      updatedAt: now,
    };

    // 13. Save to MongoDB
    const result = await appointmentsCollection.insertOne(newBooking);

    return res.status(201).send({
      success: true,
      message: "Appointment booked successfully",
      appointment: {
        _id: result.insertedId,
        ...newBooking,
      },
    });

  } catch (error) {
    console.error("Booking error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to book appointment",
    });
  }
});

app.get("/customer/dashboard-stats", verifyCustomer, async (req, res) => {
  try {
    console.log("User:", req.user);
    const email = req.user.email;

    const total = await appointmentsCollection.countDocuments({
      customerEmail: email,
    });
    const pending = await appointmentsCollection.countDocuments({
      customerEmail: email,
      status: "Pending",
    });
    const confirmed = await appointmentsCollection.countDocuments({
      customerEmail: email,
      status: "Confirmed",
    });
    const cancelled = await appointmentsCollection.countDocuments({
      customerEmail: email,
      status: "Cancelled",
    });
    res.send({
      success: true,
      stats: {
        total,
        pending,
        confirmed,
        cancelled,
      },
    });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: "Failed to fetch dashboard statistics",
    });
  }
});

app.get("/customer/appointments", verifyCustomer, async (req, res) => {
  try {
    const filter = buildAppointmentFilter(req.query, {
      customerEmail: req.user.email,
    });

    const result = await appointmentsCollection
      .find(filter)
      .sort(normalizeSort(req.query, APPOINTMENT_SORT_OPTIONS))
      .toArray();

    res.send({
      success: true,
      appointments: result,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch appointments",
    });
  }
});

app.patch("/customer/appointments/:id/cancel", verifyCustomer, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment ID",
      });
    }

    const appointmentId = new ObjectId(id);
    const appointment = await appointmentsCollection.findOne({
      _id: appointmentId,
      customerEmail: req.user.email,
    });

    if (!appointment) {
      return res.status(404).send({
        success: false,
        message: "Appointment not found",
      });
    }

    if (appointment.status !== "Pending") {
      return res.status(400).send({
        success: false,
        message: "Only pending appointments can be cancelled",
      });
    }

    const result = await appointmentsCollection.updateOne(
      {
        _id: appointmentId,
        customerEmail: req.user.email,
        status: "Pending",
      },
      {
        $set: {
          status: "Cancelled",
          cancelledAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(409).send({
        success: false,
        message: "Appointment status changed. Please refresh and try again.",
      });
    }

    const updated = await appointmentsCollection.findOne({
      _id: appointmentId,
    });

    res.send({
      success: true,
      message: "Appointment cancelled successfully",
      appointment: updated,
    });
  } catch (error) {
    console.error("Appointment cancel error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to cancel appointment",
    });
  }
});

// Payments are created through Stripe Checkout and verified by the Stripe
// webhook in the Next.js app. This legacy endpoint must not mark an
// appointment as paid without a verified Stripe payment.
app.patch("/customer/appointments/:id/pay", verifyCustomer, async (req, res) => {
  return res.status(410).send({
    success: false,
    message:
      "Payments are processed through Stripe Checkout. Open My Appointments and click Pay Now.",
  });
});



app.get("/customer/profile", verifyCustomer, async (req, res) => {
  try {
    const user = await usersCollection.findOne(
      { email: req.user.email },
      {
        projection: {
          name: 1,
          email: 1,
          image: 1,
          phone: 1,
          role: 1,
        },
      }
    );

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "User not found",
      });
    }

    res.send({
      success: true,
      user,
    });
  } catch (error) {
    console.error("Profile Fetch Error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch profile",
    });
  }
});

// ==========================
app.patch("/customer/profile", verifyCustomer, async (req, res) => {
  try {
    const { name, image, phone } = req.body;

    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).send({
        success: false,
        message: "Name is required",
      });
    }

    const result = await usersCollection.updateOne(
      { email: req.user.email },
      {
        $set: {
          name: name.trim(),
          image: typeof image === "string" ? image : "",
          phone: typeof phone === "string" ? phone : "",
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({
        success: false,
        message: "User not found",
      });
    }

    res.send({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Profile Update Error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to update profile",
    });
  }
});

// admin server code 

// List every service (active and inactive) for the admin panel.
// Supports ?search=, ?status=active|inactive and ?sort=price-asc|price-desc.
app.get("/admin/services", verifyAdmin, async (req, res) => {
  try {
    const filter = buildServiceFilter(req.query);
    const status = getServiceStatusFilter(req.query);

    if (status) {
      filter.status = status;
    }

    const hasSortParam =
      typeof req.query.sort === "string" && req.query.sort.trim();

    const sort = hasSortParam
      ? normalizeSort(req.query, SERVICE_SORT_OPTIONS)
      : { createdAt: -1, serviceName: 1 };

    const services = await servicesCollection.find(filter).sort(sort).toArray();

    res.send({
      success: true,
      services,
    });
  } catch (error) {
    console.error("Admin services fetch error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to fetch services",
    });
  }
});

// Create a new service.


// app.post("/admin/services", verifyAdmin, async (req, res) => {
//   try {
//     const { data, errors } = validateServicePayload(req.body);

//     if (errors.length > 0) {
//       return res.status(400).send({
//         success: false,
//         message: errors[0],
//         errors,
//       });
//     }

//     const now = new Date();

//     const service = {
//       ...data,
//       createdAt: now,
//       updatedAt: now,
//     };

//     const result = await servicesCollection.insertOne(service);

//     res.status(201).send({
//       success: true,
//       message: "Service created successfully",
//       service: {
//         _id: result.insertedId,
//         ...service,
//       },
//     });
//   } catch (error) {
//     console.error("Admin service create error:", error);

//     res.status(500).send({
//       success: false,
//       message: "Failed to create service",
//     });
//   }
// });


// Update an existing service.
app.patch(
  "/admin/services/:id",
  verifyAdmin,
  upload.single("image"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid service ID",
        });
      }

      const { data, errors } = validateServicePayload(req.body, {
        partial: true,
      });

      if (errors.length > 0) {
        return res.status(400).send({
          success: false,
          message: errors[0],
          errors,
        });
      }

      if (req.file) {
        data.image = await uploadToImgBB(req.file);
      } else if (String(req.body?.removeImage).toLowerCase() === "true") {
        data.image = "";
      }

      if (Object.keys(data).length === 0) {
        return res.status(400).send({
          success: false,
          message: "No valid fields were provided to update.",
        });
      }

      const result = await servicesCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            ...data,
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Service not found",
        });
      }

      const service = await servicesCollection.findOne({
        _id: new ObjectId(id),
      });

      res.send({
        success: true,
        message: "Service updated successfully",
        service,
      });
    } catch (error) {
      console.error("Admin service update error:", error);
      res.status(500).send({
        success: false,
        message: "Failed to update service",
      });
    }
  }
);

// Activate or deactivate a service. Sends an explicit status or toggles it.
app.patch("/admin/services/:id/status", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid service ID",
      });
    }

    const serviceId = new ObjectId(id);
    const service = await servicesCollection.findOne({ _id: serviceId });

    if (!service) {
      return res.status(404).send({
        success: false,
        message: "Service not found",
      });
    }

    let nextStatus;
    const requestedStatus = req.body?.status;

    if (requestedStatus !== undefined) {
      const status =
        typeof requestedStatus === "string"
          ? requestedStatus.toLowerCase()
          : "";

      if (!SERVICE_STATUSES.has(status)) {
        return res.status(400).send({
          success: false,
          message: "Status must be either active or inactive.",
        });
      }

      nextStatus = status;
    } else {
      nextStatus = service.status === "active" ? "inactive" : "active";
    }

    await servicesCollection.updateOne(
      { _id: serviceId },
      {
        $set: {
          status: nextStatus,
          updatedAt: new Date(),
        },
      }
    );

    const updated = await servicesCollection.findOne({ _id: serviceId });

    res.send({
      success: true,
      message:
        nextStatus === "active"
          ? "Service activated successfully"
          : "Service deactivated successfully",
      service: updated,
    });
  } catch (error) {
    console.error("Admin service status error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to update service status",
    });
  }
});

// Delete a service.
app.delete("/admin/services/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid service ID",
      });
    }

    const result = await servicesCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).send({
        success: false,
        message: "Service not found",
      });
    }

    res.send({
      success: true,
      message: "Service deleted successfully",
    });
  } catch (error) {
    console.error("Admin service delete error:", error);
    res.status(500).send({
      success: false,
      message: "Failed to delete service",
    });
  }
});

app.get("/admin/dashboard-stats", verifyAdmin, async (req, res) => {
  try {
    const [
      totalCustomers,
      totalActiveServices,
      totalAppointments,
      pendingAppointments,
      confirmedAppointments,
      totalSuccessfulPayments,
    ] = await Promise.all([
      usersCollection.countDocuments({
        role: "customer",
      }),

      servicesCollection.countDocuments({
        status: "active",
      }),

      appointmentsCollection.countDocuments({}),

      appointmentsCollection.countDocuments({
        status: "Pending",
      }),

      appointmentsCollection.countDocuments({
        status: "Confirmed",
      }),

      appointmentsCollection
        .aggregate([
          {
            $match: {
              paymentStatus: "Paid",
            },
          },
          {
            $group: {
              _id: null,
              total: {
                $sum: {
                  $ifNull: ["$price", { $ifNull: ["$amount", 0] }],
                },
              },
            },
          },
        ])
        .toArray(),
    ]);

    res.send({
      totalCustomers,
      totalActiveServices,
      totalAppointments,
      pendingAppointments,
      confirmedAppointments,
      totalSuccessfulPayments: totalSuccessfulPayments[0]?.total || 0,
    });
  } catch (error) {
    console.error("Admin dashboard stats error:", error);
    res.status(500).send({
      message: "Failed to load admin dashboard statistics",
    });
  }
});

// update and uploead

// app.post(
//   "/admin/services",
//   verifyAdmin,
//   upload.single("image"),
//   async (req, res) => {
//     try {
//       const {
//         name,
//         category,
//         description,
//         price,
//         duration,
//         status,
//       } = req.body;

//       // Required field validation
//       if (
//         !name ||
//         !category ||
//         !description ||
//         !price ||
//         !duration
//       ) {
//         return res.status(400).send({
//           message: "All fields are required",
//         });
//       }

//       // Number validation
//       const servicePrice = Number(price);
//       const serviceDuration = Number(duration);

//       if (
//         !Number.isFinite(servicePrice) ||
//         servicePrice <= 0 ||
//         !Number.isFinite(serviceDuration) ||
//         serviceDuration <= 0
//       ) {
//         return res.status(400).send({
//           message: "Price and duration must be greater than 0",
//         });
//       }

//       // Image validation
//       if (!req.file) {
//         return res.status(400).send({
//           message: "Service image is required",
//         });
//       }

//       // Upload image to ImgBB
//       const formData = new FormData();

//       formData.append(
//         "image",
//         new Blob([req.file.buffer], {
//           type: req.file.mimetype,
//         }),
//         req.file.originalname
//       );

//       const imageResponse = await fetch(
//         `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
//         {
//           method: "POST",
//           body: formData,
//         }
//       );

//       const imageResult = await imageResponse.json();

//       if (!imageResponse.ok || !imageResult.success) {
//         return res.status(500).send({
//           message: "Image upload failed",
//         });
//       }

//       // Save service in MongoDB
//       const newService = {
//         name: name.trim(),
//         category,
//         description: description.trim(),
//         price: servicePrice,
//         duration: serviceDuration,
//         image: imageResult.data.url,
//         status: status || "active",
//         createdAt: new Date(),
//       };

//       const result = await servicesCollection.insertOne(newService);

//       res.status(201).send({
//         success: true,
//         message: "Service added successfully",
//         insertedId: result.insertedId,
//       });
//     } catch (error) {
//       console.error("Add service error:", error);

//       res.status(500).send({
//         message: "Failed to add service",
//       });
//     }
//   }
// );



// claud ai

const uploadToImgBB = async (file) => {
  const formData = new FormData();
  formData.append(
    "image",
    new Blob([file.buffer], { type: file.mimetype }),
    file.originalname
  );

  const response = await fetch(
    `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
    { method: "POST", body: formData }
  );
  const result = await response.json();

  if (!response.ok || !result.success) {
    throw new Error("Image upload failed");
  }
  return result.data.url;
};

app.post("/admin/services", verifyAdmin,upload.single("image"),async (req, res) => {
    try {
      console.log("BODY:", req.body);
      console.log("FILE:", req.file?.originalname);

      const { data, errors } = validateServicePayload(req.body);

      if (errors.length > 0) {
        return res.status(400).send({
          success: false,
          message: errors[0],
          errors,
        });
      }

      if (!req.file) {
        return res.status(400).send({
          success: false,
          message: "Service image is required.",
        });
      }

      data.image = await uploadToImgBB(req.file);

      const now = new Date();

      const service = {
        ...data,
        createdAt: now,
        updatedAt: now,
      };

      const result = await servicesCollection.insertOne(service);

      res.status(201).send({
        success: true,
        message: "Service created successfully",
        service: {
          _id: result.insertedId,
          ...service,
        },
      });
    } catch (error) {
      console.error("Admin service create error:", error);

      res.status(500).send({
        success: false,
        message: error.message || "Failed to create service",
      });
    }
  }
);
// admin appoiment 
// ==================================
// Admin: Get All Appointments
// Supports ?search= (service name) and ?sort=price-asc|price-desc.
app.get("/admin/appointments", verifyAdmin, async (req, res) => {
  try {
    const filter = buildAppointmentFilter(req.query);

    const appointments = await appointmentsCollection
      .find(filter)
      .sort(normalizeSort(req.query, APPOINTMENT_SORT_OPTIONS))
      .toArray();

    res.send({
      success: true,
      appointments,
    });
  } catch (error) {
    console.error("Get appointments error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch appointments",
    });
  }
});


// admin appoiment : id
app.get("/admin/appointments/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment ID",
      });
    }

    const appointment = await appointmentsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!appointment) {
      return res.status(404).send({
        success: false,
        message: "Appointment not found",
      });
    }

    res.send({
      success: true,
      appointment,
    });
  } catch (error) {
    console.error("Appointment details error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch appointment details",
    });
  }
});

// /admin/appointments/:id/confirm

app.patch("/admin/appointments/:id/confirm", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment ID",
      });
    }

    const result = await appointmentsCollection.updateOne(
      {
        _id: new ObjectId(id),
        status: "Pending",
      },
      {
        $set: {
          status: "Confirmed",
          confirmedAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      const appointment = await appointmentsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!appointment) {
        return res.status(404).send({
          success: false,
          message: "Appointment not found",
        });
      }

      return res.status(400).send({
        success: false,
        message: "Only pending appointments can be confirmed",
      });
    }

    const appointment = await appointmentsCollection.findOne({
      _id: new ObjectId(id),
    });

    res.send({
      success: true,
      message: "Appointment confirmed successfully",
      appointment,
    });
  } catch (error) {
    console.error("Confirm appointment error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to confirm appointment",
    });
  }
});

// /admin/appointments/:id/confirm

app.patch("/admin/appointments/:id/cancel", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid appointment ID",
      });
    }

    const result = await appointmentsCollection.updateOne(
      {
        _id: new ObjectId(id),
        status: { $in: ["Pending", "Confirmed"] },
      },
      {
        $set: {
          status: "Cancelled",
          cancelledAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      const appointment = await appointmentsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!appointment) {
        return res.status(404).send({
          success: false,
          message: "Appointment not found",
        });
      }

      return res.status(400).send({
        success: false,
        message: "Only pending or confirmed appointments can be cancelled",
      });
    }

    const appointment = await appointmentsCollection.findOne({
      _id: new ObjectId(id),
    });

    res.send({
      success: true,
      message: "Appointment cancelled successfully",
      appointment,
    });
  } catch (error) {
    console.error("Cancel appointment error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to cancel appointment",
    });
  }
});


// admin user 

app.get("/admin/users", verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection
      .find({ role: "customer" })
      .sort({ createdAt: -1 })
      .toArray();

    res.send({ success: true, users });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: error.message,
    });
  }
});

// /admin/users/:id
app.get("/admin/users/:id", verifyAdmin, async (req, res) => {
  try {
    const user = await usersCollection.findOne({
      _id: new ObjectId(req.params.id),
      role: "customer",
    });

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "User not found",
      });
    }

    res.send({ success: true, user });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: error.message,
    });
  }
});

// /admin/users/:id/block

app.patch("/admin/users/:id/block", verifyAdmin, async (req, res) => {
  try {
    const result = await usersCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
        role: "customer",
      },
      {
        $set: {
          blocked: true,
          updatedAt: new Date(),
        },
      }
    );

    if (!result.matchedCount) {
      return res.status(404).send({
        success: false,
        message: "Customer not found",
      });
    }

    res.send({ success: true, message: "User blocked successfully" });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: error.message,
    });
  }
});

// /admin/users/:id/unblock
app.patch("/admin/users/:id/unblock", verifyAdmin, async (req, res) => {
  try {
    const result = await usersCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
        role: "customer",
      },
      {
        $set: {
          blocked: false,
          updatedAt: new Date(),
        },
      }
    );

    if (!result.matchedCount) {
      return res.status(404).send({
        success: false,
        message: "Customer not found",
      });
    }

    res.send({ success: true, message: "User unblocked successfully" });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: error.message,
    });
  }
});

// admin transitions
// Supports ?search= (service name / customer) and ?sort=price-asc|price-desc.
app.get("/admin/transactions", verifyAdmin, async (req, res) => {
  try {
    const filter = buildTransactionFilter(req.query);

    const transactions = await transactionsCollection
      .find(filter)
      .sort(normalizeSort(req.query, TRANSACTION_SORT_OPTIONS))
      .toArray();

    res.send({
      success: true,
      transactions,
    });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: error.message,
    });
  }
});
app.listen(PORT, () => {
  console.log(`SalonBook server running on port ${PORT}`);
});

export default app
