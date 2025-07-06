import mongoose from 'mongoose';

const db = async (databaseUrl: string): Promise<void> => {
  await mongoose.connect(databaseUrl, {
    serverSelectionTimeoutMS: 5000,
  });
};

export default db;
