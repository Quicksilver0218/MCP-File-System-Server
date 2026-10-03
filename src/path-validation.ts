import path from 'path';

function isPathWithinForbiddenDirectories(normalizedPath: string, forbiddenDirectories: string[]): boolean {
  return forbiddenDirectories.some(f => normalizedPath === f || normalizedPath.startsWith(f + path.sep));
}

/**
 * Checks if an absolute path is within any of the allowed directories.
 * 
 * @param absolutePath - The absolute path to check (will be normalized)
 * @param allowedDirectories - Array of absolute allowed directory paths (will be normalized)
 * @returns true if the path is within an allowed directory, false otherwise
 * @throws Error if given relative paths after normalization
 */
export function isPathAllowed(absolutePath: string, allowedDirectories: string[], forbiddenDirectories: string[]): boolean {
  // Type validation
  if (typeof absolutePath !== 'string' || !Array.isArray(allowedDirectories)) {
    return false;
  }

  // Reject empty inputs
  if (!absolutePath || allowedDirectories.length === 0) {
    return false;
  }

  // Reject null bytes (forbidden in paths)
  if (absolutePath.includes('\x00')) {
    return false;
  }

  // Normalize the input path
  let normalizedPath: string;
  try {
    normalizedPath = path.resolve(path.normalize(absolutePath));
  } catch {
    return false;
  }

  // Verify it's absolute after normalization
  if (!path.isAbsolute(normalizedPath)) {
    throw new Error('Path must be absolute after normalization');
  }

  // Check against each allowed directory
  return allowedDirectories.some(dir => {
    if (typeof dir !== 'string' || !dir) {
      return false;
    }

    // Reject null bytes in allowed dirs
    if (dir.includes('\x00')) {
      return false;
    }

    // Check if normalizedPath is within normalizedDir
    // Path is inside if it's the same or a subdirectory
    if (normalizedPath === dir) {
      return !isPathWithinForbiddenDirectories(normalizedPath, forbiddenDirectories);
    }
    
    // Special case for root directory to avoid double slash
    // On Windows, we need to check if both paths are on the same drive
    if (dir === path.sep) {
      return normalizedPath.startsWith(path.sep) && !isPathWithinForbiddenDirectories(normalizedPath, forbiddenDirectories);
    }
    
    // On Windows, also check for drive root (e.g., "C:\")
    if (path.sep === '\\' && dir.match(/^[A-Za-z]:\\?$/)) {
      // Ensure both paths are on the same drive
      const dirDrive = dir.charAt(0).toLowerCase();
      const pathDrive = normalizedPath.charAt(0).toLowerCase();
      return pathDrive === dirDrive && normalizedPath.startsWith(dir.replace(/\\?$/, '\\')) &&
        !isPathWithinForbiddenDirectories(normalizedPath, forbiddenDirectories);
    }
    
    return normalizedPath.startsWith(dir + path.sep) && !isPathWithinForbiddenDirectories(normalizedPath, forbiddenDirectories);
  });
}
