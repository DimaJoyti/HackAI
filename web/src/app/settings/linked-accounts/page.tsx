import { Metadata } from 'next'
import AccountLinking from '@/components/auth/AccountLinking'

export const metadata: Metadata = {
  title: 'Linked Accounts - HackAI',
  description: 'Manage your linked social accounts and sign-in methods.',
}

export default function LinkedAccountsPage() {
  return <AccountLinking />
}
