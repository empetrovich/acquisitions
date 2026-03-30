import logger from "#config/logger.js";
import bcrypt from 'bcrypt';
import {eq} from 'drizzle-orm';
import {db} from '#config/database.js';
import {users} from '#models/user.model.js';

/**
 * Hash password
 */
export const hashPassword = async (password) => {
    try {
        return await bcrypt.hash(password, 10);
    } catch (e) {
        logger.error(`Error hashing the password: ${e}`);
        throw new Error('Error hashing');
    }
}

/**
 * Create User
 */
export const createUser = async ({ name, email, password, role = 'user' }) => {
    try {
        const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

        if(existingUser.length > 0) { 
            throw new Error('User already exists');
        }

        const password_hash = await hashPassword(password);

        const [newUser] = await db
            .insert(users)
            .values({ name,email, password: password_hash, role })
            .returning({ id: users.id, name: users.name, email: users.email, role: users.role, created_at: users.created_at });

        logger.info(`User ${newUser.email} created successfully`);
        return newUser;

    } catch (e) {
        logger.error(`Error creating the user: ${e}`);
    }
}

/**
 * Compare plain password with hashed password
 */
export const comparePassword = async (plainPassword, hashedPassword) => {
  try{
    return await bcrypt.compare(plainPassword, hashedPassword);
  } catch(e) {
    logger.error(`Error comparing passwords: ${e}`);
  }
};


/**
 * Authenticate user by email & password
 */
export const authenticateUser = async ({ email, password }) => {
    try{
        const [existingUser] = await db.select().from(users).where(eq(users.email, email)).limit(1);

        if (!existingUser) {
            throw new Error('User not found');
        }

        const isPassValid = await comparePassword(password, existingUser.password);

        if (!isPassValid) {
            throw new Error('Invalid password');
        }

        logger.info(`User ${existingUser.email} authenticated successfully`);

        return {
            id: existingUser.id,
            name: existingUser.name,
            email: existingUser.email,
            role: existingUser.role,
            created_at: existingUser.created_at
        };

    } catch (e) {
        logger.error(`Error authenticating user: ${e}`);
    }
};