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

app.listen(PORT, () => {
  console.log(`SalonBook server running on port ${PORT}`);
});
