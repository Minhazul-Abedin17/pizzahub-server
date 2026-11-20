
import { createRemoteJWKSet, jwtVerify } from "jose";

const CLIENT_URL = process.env.CLIENT_URL;

const JWKS = createRemoteJWKSet(
  new URL(`${CLIENT_URL}/api/auth/jwks`)
);

export const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Please login first",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: CLIENT_URL,
      audience: CLIENT_URL,
    });

    req.user = {
      id: payload.id,
      email: payload.email,
      role: payload.role,
    };

    next();
  } catch {
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
};

// Role verification
export const verifyRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({
        message: "You do not have permission",
      });
    }

    next();
  };
};
