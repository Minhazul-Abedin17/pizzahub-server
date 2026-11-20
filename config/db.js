
import { MongoClient } from "mongodb";
import "dotenv/config";

const client = new MongoClient(process.env.MONGODB_URI);

export const connectToMongoDB = async () => {
  await client.connect();
  console.log("You successfully connected to MongoDB!");

  return client.db(process.env.DB_NAME);
};
