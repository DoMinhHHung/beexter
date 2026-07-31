export type WorkPreference = "remote" | "hybrid" | "onsite";
export type TalentTrack = "job_seeker" | "freelancer" | "open_to_both";
export type SkillLevel = "learning" | "working" | "advanced" | "expert";

export interface PersonalProfile {
  firstName: string;
  lastName: string;
  headline: string;
  location: string;
  about: string;
  workPreference: WorkPreference;
  talentTrack: TalentTrack;
}

export interface Skill {
  id: string;
  name: string;
  level: SkillLevel;
}

export interface Experience {
  id: string;
  role: string;
  company: string;
  startDate: string;
  endDate: string;
  current: boolean;
  description: string;
}

export interface PortfolioProject {
  id: string;
  title: string;
  description: string;
  url: string;
  tags: string[];
}

export interface SocialLinks {
  linkedin: string;
  github: string;
  website: string;
}

export interface ProfileDraft {
  personal: PersonalProfile;
  skills: Skill[];
  experiences: Experience[];
  experienceSkipped: boolean;
  projects: PortfolioProject[];
  links: SocialLinks;
  completedAt: string | null;
}
