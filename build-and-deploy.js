const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔨 Building frontend...');

try {
  // Build the frontend
  execSync('npm run build', {
    cwd: path.join(__dirname, 'Frontend'),
    stdio: 'inherit'
  });

  console.log('✅ Frontend built successfully');

  // Paths
  const frontendBuildPath = path.join(__dirname, 'Frontend', 'build');
  const backendBuildPath = path.join(__dirname, 'Backend', 'build');

  // Clear backend build folder if it exists
  if (fs.existsSync(backendBuildPath)) {
    console.log('🗑️  Clearing old backend build folder...');
    fs.rmSync(backendBuildPath, { recursive: true });
  }

  // Copy frontend build to backend
  console.log('📋 Copying build files to backend...');
  fs.cpSync(frontendBuildPath, backendBuildPath, { recursive: true });

  console.log('✅ Deploy completed successfully!');
  console.log('📂 Backend is now serving your frontend from:', backendBuildPath);

} catch (error) {
  console.error('❌ Build failed:', error.message);
  process.exit(1);
}
