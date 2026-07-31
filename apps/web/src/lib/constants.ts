import type { ProfileDraft, SkillLevel } from "@/types/profile";

export const initialProfileDraft: ProfileDraft = {
  personal: {
    firstName: "",
    lastName: "",
    headline: "",
    location: "",
    about: "",
    workPreference: "remote",
    talentTrack: "job_seeker"
  },
  skills: [],
  experiences: [],
  experienceSkipped: false,
  projects: [],
  links: {
    linkedin: "",
    github: "",
    website: ""
  },
  completedAt: null
};

export const suggestedSkills = [
  "Go",
  "TypeScript",
  "React",
  "Next.js",
  "PostgreSQL",
  "Redis",
  "Docker",
  "AWS",
  "Product Design",
  "Figma",
  "Data Analysis",
  "Project Management"
];

export const skillLevelLabels: Record<SkillLevel, string> = {
  learning: "Đang học",
  working: "Thành thạo công việc",
  advanced: "Nâng cao",
  expert: "Chuyên gia"
};

export const onboardingSteps = [
  { id: "personal", label: "Bản sắc", description: "Thông tin cá nhân" },
  { id: "skills", label: "Kỹ năng", description: "Năng lực nổi bật" },
  { id: "experience", label: "Hành trình", description: "Kinh nghiệm" },
  { id: "portfolio", label: "Tín hiệu", description: "Portfolio & liên kết" },
  { id: "review", label: "Cất cánh", description: "Kiểm tra hồ sơ" }
] as const;
