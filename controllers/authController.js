import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/db.js';

export const registerUser = async (req, res) => {
  const { email, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    'INSERT INTO Users (email, password_hash, role) VALUES ($1, $2, $3)',
    [email, hash, role]
  );

  res.status(201).json({ message: 'Registered successfully' });
};

export const loginUser = async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM Users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
};
