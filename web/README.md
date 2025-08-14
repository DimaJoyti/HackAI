# HackAI Frontend

Modern React/Next.js frontend for the HackAI Educational Cybersecurity AI Platform.

## 🚀 Features

### ✅ **Completed Components**

#### **Core Infrastructure**
- **Next.js 14** with App Router and TypeScript
- **TailwindCSS** with custom design system
- **Radix UI** components for accessibility
- **React Query** for data fetching and caching
- **React Hook Form** with Zod validation
- **Next Themes** for dark/light mode support

#### **Authentication System**
- **Login/Register** pages with form validation
- **JWT token management** with automatic refresh
- **Protected routes** with authentication guards
- **Role-based access control** (Admin, Moderator, User, Guest)

#### **Dashboard Layout**
- **Responsive sidebar** navigation
- **Mobile-friendly** hamburger menu
- **User profile** display and management
- **Real-time notifications** indicator
- **Search functionality** in header

#### **Security Scanning Interface**
- **Vulnerability Scan** configuration and management
- **Real-time progress** tracking with progress bars
- **Scan history** with status indicators
- **Interactive scan results** with severity badges
- **Scan type selection** (Web, API, SSL, Directory)

#### **Dashboard Overview**
- **Welcome dashboard** with user greeting
- **Quick action cards** for starting scans
- **Statistics overview** with key metrics
- **Recent scans** and vulnerabilities display
- **Learning modules** integration

#### **UI Components Library**
- **Button** with loading states and variants
- **Card** components for content organization
- **Badge** with security severity variants
- **Input/Textarea** with validation styling
- **Select** dropdown with search
- **Progress** bars for scan tracking
- **Label** components for forms

#### **Design System**
- **Security-themed** color palette
- **Severity indicators** (Critical, High, Medium, Low, Info)
- **Scan status** indicators (Running, Completed, Failed, Cancelled)
- **Dark/Light mode** support
- **Responsive design** for all screen sizes
- **Accessibility** features throughout

## 🛠️ Technology Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: TailwindCSS with custom utilities
- **Components**: Radix UI primitives
- **Forms**: React Hook Form + Zod validation
- **State**: Zustand for global state
- **Data Fetching**: React Query
- **Icons**: Heroicons
- **Themes**: Next Themes

## 📁 Project Structure

```
web/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── auth/              # Authentication pages
│   │   ├── dashboard/         # Dashboard pages
│   │   ├── layout.tsx         # Root layout
│   │   ├── page.tsx           # Home page
│   │   └── globals.css        # Global styles
│   ├── components/            # Reusable components
│   │   ├── ui/               # UI component library
│   │   └── providers.tsx     # Context providers
│   ├── hooks/                # Custom React hooks
│   │   └── use-auth.tsx      # Authentication hook
│   └── lib/                  # Utilities and configurations
│       ├── api.ts            # API client
│       └── utils.ts          # Helper functions
├── public/                   # Static assets
├── package.json             # Dependencies
├── tailwind.config.js       # TailwindCSS configuration
├── tsconfig.json           # TypeScript configuration
└── next.config.js          # Next.js configuration
```

## 🚦 Getting Started

### Prerequisites
- Node.js 18+
- npm or yarn

### Installation

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Set environment variables**
   ```bash
   cp .env.example .env.local
   ```
   
   Configure the following variables:
   ```env
   NEXT_PUBLIC_API_URL=http://localhost:8080
   NEXT_PUBLIC_WS_URL=ws://localhost:8080
   ```

3. **Start development server**
   ```bash
   npm run dev
   ```

4. **Open in browser**
   ```
   http://localhost:3000
   ```

### Build for Production

```bash
npm run build
npm start
```

## 📱 Pages & Features

### **Landing Page** (`/`)
- Hero section with platform introduction
- Feature highlights with icons
- Statistics showcase
- Call-to-action buttons
- Responsive design

### **Authentication** (`/auth/login`, `/auth/register`)
- Login form with email/password
- Registration form with validation
- Demo credentials display
- Password visibility toggle
- Remember me functionality

### **Dashboard Overview** (`/dashboard`)
- Welcome message with user name
- Quick action cards for scans
- Key metrics display
- Recent scans list
- Recent vulnerabilities
- Learning module recommendations

### **Vulnerability Scanning** (`/dashboard/scans/vulnerability`)
- Scan configuration form
- Target URL input with validation
- Scan type selection
- Scan history table
- Real-time progress tracking
- Results visualization

## 🎨 Design System

### **Colors**
- **Brand**: Blue gradient (#0ea5e9 to #0369a1)
- **Security Severities**:
  - Critical: Red (#dc2626)
  - High: Orange (#ea580c)
  - Medium: Yellow (#d97706)
  - Low: Blue (#2563eb)
  - Info: Gray (#6b7280)

### **Components**
- **Buttons**: Multiple variants with loading states
- **Cards**: Hover effects and proper spacing
- **Badges**: Color-coded for different statuses
- **Forms**: Validation styling and error states
- **Navigation**: Active state indicators

### **Responsive Design**
- **Mobile**: Hamburger menu, stacked layout
- **Tablet**: Adaptive sidebar, optimized spacing
- **Desktop**: Full sidebar, multi-column layouts

## 🔧 Development

### **Available Scripts**
- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint
- `npm run type-check` - Run TypeScript checks

### **Code Quality**
- **ESLint** for code linting
- **Prettier** for code formatting
- **TypeScript** for type safety
- **Husky** for git hooks (if configured)

## 🚀 Deployment

### **Docker**
```bash
docker build -t hackai-web .
docker run -p 3000:3000 hackai-web
```

### **Environment Variables**
- `NEXT_PUBLIC_API_URL` - Backend API URL
- `NEXT_PUBLIC_WS_URL` - WebSocket URL
- `NODE_ENV` - Environment (development/production)

## 🔮 Future Enhancements

- **Real-time WebSocket** integration
- **Advanced charts** and analytics
- **File upload** components
- **Notification system** with toast messages
- **Advanced filtering** and search
- **Export functionality** for reports
- **Internationalization** (i18n)
- **Progressive Web App** (PWA) features

## 📝 Notes

- The frontend is designed to work with the HackAI Go backend
- All API calls are mocked for development
- Authentication state is managed globally
- Components are built with accessibility in mind
- The design follows modern cybersecurity UI patterns

---

**Built with ❤️ for cybersecurity education**
