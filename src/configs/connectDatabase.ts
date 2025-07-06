import mongoose from 'mongoose';

const connectDatabase = async (databaseUrl: string): Promise<void> => {
  try {
    await mongoose.connect(databaseUrl, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

export default connectDatabase;
