import {z} from 'zod'

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email("Please provide a valid email!");

export const zodEmail = z.object({
  email: emailSchema,
});

export const zodVerification = z.object({
  verificationToken: z.number("Provide a valid number!"),
});

export const zodPassword = z.object({
  password: z.string().min(6, "Password must me atleast 6 digit long!"),
});

export const zodResetPass = z.object({
  password: z.string().min(6, "Password must me atleast 6 digit long!"),
  verificationToken: z.number("Provide a valid number!"),
});