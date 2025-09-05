import { Metadata } from 'next'
import ProfileManagement from '@/components/user/ProfileManagement'

export const metadata: Metadata = {
  title: 'Profile Settings - HackAI',
  description: 'Manage your profile information and account settings.',
}

export default function ProfilePage() {
  return <ProfileManagement />
}
