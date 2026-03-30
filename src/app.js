import express from 'express';
import logger from '#config/logger.js';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from '#routes/auth.routes.js'
//import { timestamp } from 'drizzle-orm/gel-core';

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

//passing morgan messages to our logger
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) }}));

app.get('/', (req, res) => {
  logger.info('Hello from Acquisitions logs!');

  res.status(200).send('Hello from Acquisition!');
});

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

app.get('/api', (req, res) => {
    res.status(200).json({ message: 'Acquisition API is running!' });
});

app.use('/api/auth', authRoutes); // all requests within this router witll start with /api/auth

export default app;