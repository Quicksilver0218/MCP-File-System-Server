import path from 'path';

function isPathWithinForbiddenPaths(normalizedPath: string, forbiddenPaths: Iterable<string>): boolean {
  for (const f of forbiddenPaths)
    if (normalizedPath === f || normalizedPath.startsWith(f + path.sep))
      return true;
  return false;
}

/**
 * Checks if an absolute path is within any of the allowed paths.
 * 
 * @param absolutePath - The absolute path to check (will be normalized)
 * @param allowedPaths - Array of absolute normalized allowed paths
 * @param forbiddenPaths - Array of absolute normalized forbidden paths
 * @returns true if the path is within an allowed directory, false otherwise
 * @throws Error if given relative paths after normalization
 */
export function isPathAllowed(absolutePath: string, allowedPaths: Iterable<string>, forbiddenPaths: Iterable<string>): boolean | null {
  // Type validation
  if (typeof absolutePath !== 'string')
    return null;

  const paths = [...allowedPaths];
  // Reject empty inputs
  if (!absolutePath || paths.length === 0)
    return null;

  // Reject null bytes (forbidden in paths)
  if (absolutePath.includes('\x00'))
    return null;

  // Normalize the input path
  let normalizedPath: string;
  try {
    normalizedPath = path.resolve(path.normalize(absolutePath));
  } catch {
    return null;
  }

  // Verify it's absolute after normalization
  if (!path.isAbsolute(normalizedPath)) {
    throw new Error('Path must be absolute after normalization');
  }

  // Check against each allowed directory
  return paths.some(dir => {
    if (typeof dir !== 'string' || !dir)
      return null;

    // Reject null bytes in allowed dirs
    if (dir.includes('\x00'))
      return null;

    // Check if normalizedPath is within normalizedDir
    // Path is inside if it's the same or a subdirectory
    if (normalizedPath === dir)
      return !isPathWithinForbiddenPaths(normalizedPath, forbiddenPaths);

    // Special case for root directory to avoid double slash
    // On Windows, we need to check if both paths are on the same drive
    if (dir === path.sep) {
      if (normalizedPath.startsWith(path.sep))
        return !isPathWithinForbiddenPaths(normalizedPath, forbiddenPaths);
      return null;
    }

    // On Windows, also check for drive root (e.g., "C:\")
    if (path.sep === '\\' && dir.match(/^[A-Za-z]:\\?$/)) {
      // Ensure both paths are on the same drive
      const dirDrive = dir.charAt(0).toLowerCase();
      const pathDrive = normalizedPath.charAt(0).toLowerCase();
      if (pathDrive === dirDrive && normalizedPath.startsWith(dir.replace(/\\?$/, '\\')))
        return !isPathWithinForbiddenPaths(normalizedPath, forbiddenPaths);
      return null;
    }

    if (normalizedPath.startsWith(dir + path.sep))
      return !isPathWithinForbiddenPaths(normalizedPath, forbiddenPaths);
    return null;
  });
}
