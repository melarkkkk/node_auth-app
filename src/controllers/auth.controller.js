import { User } from '../models/user.js';
import { userService } from '../services/user.service.js';
import { jwtService } from '../services/jwt.service.js';
import { ApiError } from '../exeptions/api.error.js';
import bcrypt from 'bcrypt';
import { tokenService } from '../services/token.service.js';

const validateEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return 'Email is required';
  }

  const trimmed = email.trim();

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailRegex.test(trimmed)) {
    return 'Invalid email format';
  }

  return null;
};

const validatePassword = (password) => {
  if (!password || typeof password !== 'string') {
    return 'Password is required';
  }

  const trimmed = password.trim();

  if (trimmed.length < 8) {
    return 'Password must be at least 8 characters long';
  }

  if (/\s/.test(trimmed)) {
    return 'Password must not contain spaces';
  }

  if (!/[A-Z]/.test(trimmed)) {
    return 'Password must contain at least one uppercase letter';
  }

  if (!/[a-z]/.test(trimmed)) {
    return 'Password must contain at least one lowercase letter';
  }

  if (!/[0-9]/.test(trimmed)) {
    return 'Password must contain at least one digit';
  }

  if (!/[!@#$%^&*(),.?":{}|<>_\-+=/[\]]/.test(trimmed)) {
    return 'Password must contain at least one special character';
  }

  const forbidden = ['password', 'qwerty', '12345678', '11111111', 'asdfghjk'];

  if (forbidden.some((f) => trimmed.toLowerCase().includes(f))) {
    return 'Password is too weak';
  }

  return null;
};

const register = async (req, res) => {
  const { email, password } = req.body;
  const errors = {
    email: validateEmail(email),
    password: validatePassword(password),
  };

  if (errors.email || errors.password) {
    throw ApiError.badRequest('Bad request', errors);
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await userService.register(email, hashedPassword);
  res.status(201).json({ message: 'OK' });
};

const activate = async (req, res) => {
  const { activationToken } = req.params;
  const user = await User.findOne({
    where: { activationToken },
  });

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  user.activationToken = null;
  user.save();

  return res.status(200).json(user);
};

const login = async (req, res) => {
  const { email, password } = req.body;

  const user = await userService.findByEmail(email);

  if (!user) {
    throw ApiError.badRequest('User not found');
  }

  const isPasswordValid = bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw ApiError.badRequest('Wrong password');
  }

  generateTokens(res, user);
};

const refresh = async (req, res) => {
  const { refreshToken } = req.cookies;

  const user = jwtService.verifyRefresh(refreshToken);

  const token = await tokenService.getByToken(refreshToken);

  if (!user || !token) {
    throw ApiError.unauthorized();
  }

  generateTokens(res, user);
};

const generateTokens = async (res, user) => {
  const normalizedUser = userService.normalize(user);
  const accessToken = jwtService.sign(normalizedUser);
  const refreshAccessToken = jwtService.signRefresh(normalizedUser);

  await tokenService.save(normalizedUser.id, refreshAccessToken);

  res.cookie('refreshToken', refreshAccessToken, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    HttpOnly: true,
  });

  return res.status(200).json({
    user: normalizedUser,
    accessToken,
  });
};

const logout = async (req, res) => {
  const { refreshToken } = req.cookies;
  const user = await jwtService.verifyRefresh(refreshToken);

  if (!user || !refreshToken) {
    throw ApiError.unauthorized();
  }

  await tokenService.remove(user.id);

  return res.status(200);
};

export const authController = {
  register,
  activate,
  login,
  refresh,
  logout,
};
