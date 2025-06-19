# Tape - Full Stack Application

A full-stack application with a React Native frontend and Node.js backend.

## Project Structure

```
tape/
├── frontend/          # React Native application
│   ├── app/          # Main application screens
│   ├── components/   # Reusable UI components
│   ├── services/     # API services
│   ├── hooks/        # Custom React hooks
│   ├── context/      # React context providers
│   ├── constants/    # Application constants
│   ├── assets/       # Images, fonts, etc.
│   └── scripts/      # Build and utility scripts
└── backend/          # Node.js server
    ├── config/       # Configuration files
    ├── migrations/   # Database migrations
    └── index.js      # Main server file
```

## Frontend (React Native)

The frontend is built with React Native and Expo.

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Expo CLI

### Installation

```bash
cd frontend
npm install
```

### Running the Frontend

```bash
# Start the development server
npm start

# Run on iOS simulator
npm run ios

# Run on Android emulator
npm run android

# Run on web
npm run web
```

## Backend (Node.js)

The backend is a Node.js server with Express.

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn

### Installation

```bash
cd backend
npm install
```

### Running the Backend

```bash
# Start the development server
npm start

# Run with nodemon for development
npm run dev
```

## Environment Variables

Create `.env` files in both frontend and backend directories with the necessary environment variables.

### Backend Environment Variables

```env
PORT=3000
NODE_ENV=development
# Add other environment variables as needed
```

### Frontend Environment Variables

```env
EXPO_PUBLIC_API_URL=http://localhost:3000
# Add other environment variables as needed
```

## Database

The backend includes database migrations and configuration. Make sure to set up your database connection in the backend configuration.

## Development

### Code Style

- Frontend: Follow React Native and TypeScript best practices
- Backend: Follow Node.js and Express best practices
- Use ESLint and Prettier for code formatting

### Testing

```bash
# Frontend tests
cd frontend
npm test

# Backend tests
cd backend
npm test
```

## Deployment

### Frontend Deployment

The frontend can be deployed using Expo's build service or by building standalone apps.

### Backend Deployment

The backend can be deployed to various platforms like:
- Heroku
- Vercel
- Railway
- DigitalOcean
- AWS

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License. 