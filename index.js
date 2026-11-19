import express from "express";
import { MongoClient, ObjectId } from 'mongodb';
import cors from "cors";
import "dotenv/config";

const PORT = process.env.PORT || 5000;
const app = express();

// Middleware
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
}));
app.use(express.json());
// Test route


// verifyToken
const verifyCustomer = (req, res, next) => {
  if (req.user.role === "admin") {
    return res.status(403).send({
      message: "Admins cannot book appointments",
    });
  }

  next();
};

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


// services/Featured 
app.get("/services/Featured", async (req, res) => {
  try {
    const result = await servicesCollection
      .find({ status: "active" })
      .limit(6)
      .toArray();

    res.send(result);
  } catch (error) {
    res.status(500).send({
      message: "Failed to fetch featured services",
    });
  }
});

// Services 
app.get("/services", async (req, res) => {
  const result = await servicesCollection
    .find({ status: "active" })
    .toArray();

  res.send(result);
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
    const service = await servicesCollection.findOne({
      _id: new ObjectId(id),
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
app.post("/bookings", async (req, res) => {
  try {
    const bookingData = req.body;

    const newBooking = {
      ...bookingData,
      status: "Pending",
      createdAt: new Date(),
    };

    const result = await appointmentsCollection.insertOne(newBooking);

    res.status(201).send({
      success: true,
      message: "Appointment booked successfully",
      insertedId: result.insertedId,
    });
  } catch (error) {
    console.error(error);

    res.status(500).send({
      success: false,
      message: "Failed to book appointment",
    });
  }
});


// app.get("/customer/dashboard-stats", verifyCustomer, async (req, res) => {
//   try {
//     const email = req.user.email;

//     const total = await appointmentsCollection.countDocuments({
//       customerEmail: email,
//     });
//     const pending = await appointmentsCollection.countDocuments({
//       customerEmail: email,
//       status: "Pending",
//     });
//     const confirmed = await appointmentsCollection.countDocuments({
//       customerEmail: email,
//       status: "Confirmed",
//     });
//     const cancelled = await appointmentsCollection.countDocuments({
//       customerEmail: email,
//       status: "Cancelled",
//     });
//     res.send({
//       success: true,
//       stats: {
//         total,
//         pending,
//         confirmed,
//         cancelled,
//       },
//     });
//   } catch (error) {
//     res.status(500).send({
//       success: false,
//       message: "Failed to fetch dashboard statistics",
//     });
//   }
// });


app.get("/customer/dashboard-stats", verifyCustomer, async (req, res) => {
  try {
    // Temporary testing only
    const total = await appointmentsCollection.countDocuments();

    const pending = await appointmentsCollection.countDocuments({
      status: "Pending",
    });

    const confirmed = await appointmentsCollection.countDocuments({
      status: "Confirmed",
    });

    const cancelled = await appointmentsCollection.countDocuments({
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
    console.error(error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch dashboard statistics",
    });
  }
});


// /customer/appointments
app.get("/customer/appointments", verifyCustomer, async (req, res) => {
  try {
    const result = await appointmentsCollection
      .find({})
      .sort({ createdAt: -1 })
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
app.listen(PORT, () => {
  console.log(`SalonBook server running on port ${PORT}`);
});
