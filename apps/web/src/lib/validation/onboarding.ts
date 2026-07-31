import { z } from "zod";

export const personalProfileSchema = z.object({
  firstName: z.string().trim().min(1, "Nhập tên của bạn").max(80, "Tên quá dài"),
  lastName: z.string().trim().min(1, "Nhập họ của bạn").max(80, "Họ quá dài"),
  headline: z.string().trim().min(6, "Headline cần ít nhất 6 ký tự").max(120, "Headline tối đa 120 ký tự"),
  location: z.string().trim().min(2, "Nhập địa điểm hiện tại").max(120, "Địa điểm quá dài"),
  about: z.string().trim().min(40, "Giới thiệu cần ít nhất 40 ký tự").max(600, "Giới thiệu tối đa 600 ký tự"),
  workPreference: z.enum(["remote", "hybrid", "onsite"]),
  talentTrack: z.enum(["job_seeker", "freelancer", "open_to_both"])
});

export type PersonalProfileValues = z.infer<typeof personalProfileSchema>;

export const signInSchema = z.object({
  email: z.string().trim().email("Email chưa đúng định dạng"),
  password: z.string().min(8, "Mật khẩu cần ít nhất 8 ký tự").max(128, "Mật khẩu quá dài")
});

export type SignInValues = z.infer<typeof signInSchema>;

const accountPasswordSchema = z
  .string()
  .min(8, "Mật khẩu cần ít nhất 8 ký tự")
  .max(128, "Mật khẩu quá dài")
  .regex(/[A-Z]/, "Cần ít nhất một chữ hoa")
  .regex(/[a-z]/, "Cần ít nhất một chữ thường")
  .regex(/[0-9]/, "Cần ít nhất một chữ số")
  .regex(/[^A-Za-z0-9]/, "Cần ít nhất một ký tự đặc biệt");

export const signUpSchema = z
  .object({
    email: z.string().trim().email("Email chưa đúng định dạng").max(254, "Email quá dài"),
    password: accountPasswordSchema,
    confirmPassword: z.string()
  })
  .refine((value) => value.password === value.confirmPassword, {
    message: "Mật khẩu xác nhận chưa khớp",
    path: ["confirmPassword"]
  });

export type SignUpValues = z.infer<typeof signUpSchema>;

export const forgotPasswordSchema = z.object({
  email: z.string().trim().email("Email chưa đúng định dạng").max(254, "Email quá dài")
});

export type ForgotPasswordValues = z.infer<typeof forgotPasswordSchema>;

export const resetPasswordSchema = z
  .object({
    password: accountPasswordSchema,
    confirmPassword: z.string()
  })
  .refine((value) => value.password === value.confirmPassword, {
    message: "Mật khẩu xác nhận chưa khớp",
    path: ["confirmPassword"]
  });

export type ResetPasswordValues = z.infer<typeof resetPasswordSchema>;
