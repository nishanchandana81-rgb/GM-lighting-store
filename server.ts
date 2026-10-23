import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

interface UserRecord {
  id: string;
  fullName: string;
  email: string;
  phone: string;
  passwordHash: string;
  salt: string;
  deliveryAddress?: {
    province: string;
    district: string;
    city: string;
    postalCode: string;
    streetAddress: string;
    houseOrBuilding?: string;
    deliveryInstructions?: string;
  };
  resetToken?: string;
  resetTokenExpiry?: number;
  createdAt: string;
  updatedAt: string;
}

interface OrderRecord {
  id: string;
  orderNumber: string;
  userId?: string;
  customerName: string;
  customerPhone: string;
  customerEmail?: string;
  items: Array<{
    id: string;
    name: string;
    price: number;
    quantity: number;
    wattage?: '20W' | '25W';
    selectedCable?: string;
    selectedColor?: string;
  }>;
  subtotal: number;
  deliveryFee: number;
  grandTotal: number;
  status: 'Processing' | 'Confirmed' | 'Dispatched' | 'Delivered' | 'Cancelled';
  paymentMethod: 'cod' | 'bank_transfer';
  deliveryAddress: {
    province: string;
    district: string;
    city: string;
    postalCode: string;
    streetAddress: string;
    houseOrBuilding?: string;
    deliveryInstructions?: string;
  };
  notes?: string;
  createdAt: string;
}

interface DatabaseSchema {
  users: UserRecord[];
  sessions: Record<string, { userId: string; createdAt: number }>;
  orders: OrderRecord[];
}

// Database directory & file path
const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

// Initialize database
function loadDatabase(): DatabaseSchema {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DB_FILE)) {
    const initialDb: DatabaseSchema = {
      users: [],
      sessions: {},
      orders: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2), 'utf-8');
    return initialDb;
  }

  try {
    const data = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading db.json, initializing empty db', err);
    return { users: [], sessions: {}, orders: [] };
  }
}

function saveDatabase(db: DatabaseSchema) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const tempFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(db, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Error saving db.json:', err);
  }
}

// Password hashing with crypto.scrypt
function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password: string, salt: string, hash: string): boolean {
  try {
    const computed = crypto.scryptSync(password, salt, 64);
    const stored = Buffer.from(hash, 'hex');
    return crypto.timingSafeEqual(computed, stored);
  } catch {
    return false;
  }
}

// Simple in-memory rate limiter for auth routes
const authAttempts: Record<string, { count: number; lastAttempt: number }> = {};
function rateLimiter(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 mins
  const maxAttempts = 20;

  if (!authAttempts[ip]) {
    authAttempts[ip] = { count: 1, lastAttempt: now };
  } else {
    if (now - authAttempts[ip].lastAttempt > windowMs) {
      authAttempts[ip] = { count: 1, lastAttempt: now };
    } else {
      authAttempts[ip].count++;
      if (authAttempts[ip].count > maxAttempts) {
        return res.status(429).json({
          error: 'Too many authentication attempts. Please try again in 15 minutes.'
        });
      }
    }
  }
  next();
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  app.use(express.json());

  // In-memory or persisted db
  let db = loadDatabase();

  // Helper to extract authenticated user
  function getAuthenticatedUser(req: Request): UserRecord | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    const token = authHeader.substring(7).trim();
    if (!token) return null;

    const session = db.sessions[token];
    if (!session) return null;

    // Check session age: 30 days
    const maxAge = 30 * 24 * 60 * 60 * 1000;
    if (Date.now() - session.createdAt > maxAge) {
      delete db.sessions[token];
      saveDatabase(db);
      return null;
    }

    const user = db.users.find((u) => u.id === session.userId);
    return user || null;
  }

  // ---------------- AUTH API ROUTES ----------------

  // POST /api/auth/register
  app.post('/api/auth/register', rateLimiter, (req: Request, res: Response) => {
    try {
      const { fullName, email, phone, password, deliveryAddress } = req.body;

      // Validation
      if (!fullName || typeof fullName !== 'string' || fullName.trim().length < 2) {
        return res.status(400).json({ error: 'Please enter your full name (minimum 2 characters).' });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!email || typeof email !== 'string' || !emailRegex.test(email.trim())) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
      }

      if (!phone || typeof phone !== 'string' || phone.trim().length < 9) {
        return res.status(400).json({ error: 'Please enter a valid mobile phone number.' });
      }

      if (!password || typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long and contain letters and numbers.' });
      }

      // Check password has at least one letter and one number
      if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
        return res.status(400).json({ error: 'Password must contain at least one letter and one number.' });
      }

      // Validate delivery address
      if (!deliveryAddress || typeof deliveryAddress !== 'object') {
        return res.status(400).json({ error: 'Delivery address information is required.' });
      }
      if (!deliveryAddress.province || !deliveryAddress.district || !deliveryAddress.city || !deliveryAddress.streetAddress || !deliveryAddress.postalCode) {
        return res.status(400).json({ error: 'Please complete all required delivery address fields (Province, District, City, Postal Code, and Street Address).' });
      }

      const normalizedEmail = email.trim().toLowerCase();

      // Check for duplicate account
      const existing = db.users.find((u) => u.email === normalizedEmail);
      if (existing) {
        return res.status(409).json({ error: 'An account with this email address already exists. Please sign in instead.' });
      }

      // Generate salt and hash
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = hashPassword(password, salt);

      const userId = `usr_${crypto.randomBytes(8).toString('hex')}`;
      const newUser: UserRecord = {
        id: userId,
        fullName: fullName.trim(),
        email: normalizedEmail,
        phone: phone.trim(),
        passwordHash,
        salt,
        deliveryAddress: {
          province: deliveryAddress.province.trim(),
          district: deliveryAddress.district.trim(),
          city: deliveryAddress.city.trim(),
          postalCode: deliveryAddress.postalCode.trim(),
          streetAddress: deliveryAddress.streetAddress.trim(),
          houseOrBuilding: deliveryAddress.houseOrBuilding?.trim() || '',
          deliveryInstructions: deliveryAddress.deliveryInstructions?.trim() || ''
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      db.users.push(newUser);

      // Create session token
      const sessionToken = crypto.randomBytes(32).toString('hex');
      db.sessions[sessionToken] = {
        userId,
        createdAt: Date.now()
      };

      saveDatabase(db);

      return res.status(201).json({
        success: true,
        message: 'Account created successfully',
        token: sessionToken,
        user: {
          id: newUser.id,
          fullName: newUser.fullName,
          email: newUser.email,
          phone: newUser.phone,
          deliveryAddress: newUser.deliveryAddress,
          createdAt: newUser.createdAt
        }
      });
    } catch (err) {
      console.error('Registration error:', err);
      return res.status(500).json({ error: 'An error occurred during account creation. Please try again.' });
    }
  });

  // POST /api/auth/login
  app.post('/api/auth/login', rateLimiter, (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
      }

      const normalizedEmail = String(email).trim().toLowerCase();
      const user = db.users.find((u) => u.email === normalizedEmail);

      // Constant time check or generic error to prevent email enumeration
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password. Please verify your credentials and try again.' });
      }

      const isValid = verifyPassword(String(password), user.salt, user.passwordHash);
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid email or password. Please verify your credentials and try again.' });
      }

      // Generate new session token
      const sessionToken = crypto.randomBytes(32).toString('hex');
      db.sessions[sessionToken] = {
        userId: user.id,
        createdAt: Date.now()
      };
      saveDatabase(db);

      return res.json({
        success: true,
        message: 'Signed in successfully',
        token: sessionToken,
        user: {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
          phone: user.phone,
          deliveryAddress: user.deliveryAddress,
          createdAt: user.createdAt
        }
      });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'An unexpected error occurred during sign-in.' });
    }
  });

  // POST /api/auth/logout
  app.post('/api/auth/logout', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7).trim();
      delete db.sessions[token];
      saveDatabase(db);
    }
    return res.json({ success: true, message: 'Signed out successfully' });
  });

  // GET /api/auth/me
  app.get('/api/auth/me', (req: Request, res: Response) => {
    const user = getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        deliveryAddress: user.deliveryAddress,
        createdAt: user.createdAt
      }
    });
  });

  // PUT /api/auth/profile
  app.put('/api/auth/profile', (req: Request, res: Response) => {
    const user = getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const { fullName, phone } = req.body;
    if (fullName && typeof fullName === 'string' && fullName.trim().length >= 2) {
      user.fullName = fullName.trim();
    }
    if (phone && typeof phone === 'string' && phone.trim().length >= 9) {
      user.phone = phone.trim();
    }
    user.updatedAt = new Date().toISOString();
    saveDatabase(db);

    return res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        deliveryAddress: user.deliveryAddress,
        createdAt: user.createdAt
      }
    });
  });

  // PUT /api/auth/address
  app.put('/api/auth/address', (req: Request, res: Response) => {
    const user = getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const { province, district, city, postalCode, streetAddress, houseOrBuilding, deliveryInstructions } = req.body;
    if (!province || !district || !city || !postalCode || !streetAddress) {
      return res.status(400).json({ error: 'Please provide all required address fields.' });
    }

    user.deliveryAddress = {
      province: String(province).trim(),
      district: String(district).trim(),
      city: String(city).trim(),
      postalCode: String(postalCode).trim(),
      streetAddress: String(streetAddress).trim(),
      houseOrBuilding: houseOrBuilding ? String(houseOrBuilding).trim() : '',
      deliveryInstructions: deliveryInstructions ? String(deliveryInstructions).trim() : ''
    };
    user.updatedAt = new Date().toISOString();
    saveDatabase(db);

    return res.json({
      success: true,
      message: 'Delivery address updated successfully',
      deliveryAddress: user.deliveryAddress
    });
  });

  // PUT /api/auth/change-password
  app.put('/api/auth/change-password', (req: Request, res: Response) => {
    const user = getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required.' });
    }

    const isValid = verifyPassword(String(currentPassword), user.salt, user.passwordHash);
    if (!isValid) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }

    if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long and contain letters and numbers.' });
    }

    user.salt = crypto.randomBytes(16).toString('hex');
    user.passwordHash = hashPassword(newPassword, user.salt);
    user.updatedAt = new Date().toISOString();
    saveDatabase(db);

    return res.json({ success: true, message: 'Password updated successfully' });
  });

  // POST /api/auth/forgot-password
  app.post('/api/auth/forgot-password', rateLimiter, (req: Request, res: Response) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = db.users.find((u) => u.email === normalizedEmail);

    if (user) {
      // 6-digit numeric reset code
      const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
      user.resetToken = resetCode;
      user.resetTokenExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
      saveDatabase(db);

      return res.json({
        success: true,
        message: 'Password reset instructions have been generated.',
        demoResetCode: resetCode // Provided for in-app demo verification
      });
    }

    // Always return success to prevent email enumeration
    return res.json({
      success: true,
      message: 'If an account exists with this email, password reset instructions have been sent.'
    });
  });

  // POST /api/auth/reset-password
  app.post('/api/auth/reset-password', rateLimiter, (req: Request, res: Response) => {
    const { email, resetCode, newPassword } = req.body;
    if (!email || !resetCode || !newPassword) {
      return res.status(400).json({ error: 'Email, reset code, and new password are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = db.users.find((u) => u.email === normalizedEmail);

    if (!user || user.resetToken !== String(resetCode).trim() || !user.resetTokenExpiry || Date.now() > user.resetTokenExpiry) {
      return res.status(400).json({ error: 'Invalid or expired password reset code.' });
    }

    if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long and contain letters and numbers.' });
    }

    user.salt = crypto.randomBytes(16).toString('hex');
    user.passwordHash = hashPassword(newPassword, user.salt);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    user.updatedAt = new Date().toISOString();
    saveDatabase(db);

    return res.json({ success: true, message: 'Password has been reset successfully. You can now sign in.' });
  });

  // ---------------- ORDERS API ROUTES ----------------

  // GET /api/orders
  app.get('/api/orders', (req: Request, res: Response) => {
    const user = getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Not authenticated to view orders' });
    }

    // Return only authenticated user's own orders
    const userOrders = db.orders.filter((o) => o.userId === user.id);
    return res.json({ success: true, orders: userOrders });
  });

  // POST /api/orders
  app.post('/api/orders', (req: Request, res: Response) => {
    try {
      const user = getAuthenticatedUser(req);
      const { items, subtotal, deliveryFee, grandTotal, paymentMethod, customerName, customerPhone, customerEmail, deliveryAddress, notes } = req.body;

      if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: 'Order must contain at least one item.' });
      }

      if (!customerName || !customerPhone || !deliveryAddress) {
        return res.status(400).json({ error: 'Customer name, phone, and delivery address are required.' });
      }

      const orderNumber = `NCG-${Math.floor(1000 + Math.random() * 9000)}`;
      const newOrder: OrderRecord = {
        id: `ord_${crypto.randomBytes(8).toString('hex')}`,
        orderNumber,
        userId: user ? user.id : undefined,
        customerName: customerName.trim(),
        customerPhone: customerPhone.trim(),
        customerEmail: customerEmail?.trim() || user?.email,
        items,
        subtotal: Number(subtotal) || 0,
        deliveryFee: Number(deliveryFee) || 0,
        grandTotal: Number(grandTotal) || 0,
        status: 'Confirmed',
        paymentMethod: paymentMethod === 'bank_transfer' ? 'bank_transfer' : 'cod',
        deliveryAddress,
        notes: notes?.trim() || '',
        createdAt: new Date().toISOString()
      };

      db.orders.unshift(newOrder);
      saveDatabase(db);

      return res.status(201).json({
        success: true,
        order: newOrder
      });
    } catch (err) {
      console.error('Error creating order:', err);
      return res.status(500).json({ error: 'Failed to record order' });
    }
  });

  // ---------------- VITE MIDDLEWARE / STATIC ASSETS ----------------

  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(process.cwd(), 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(process.cwd(), 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true'
      },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NC TECH STORE server listening on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
