import fs from "fs/promises";
import path from "path";
import { randomBytes } from 'crypto';
import { createTwoFilesPatch } from 'diff';
import { minimatch } from 'minimatch';
import { normalizePath, expandHome } from './path-utils.js';
import { isPathWithinAllowedDirectories } from './path-validation.js';

// Global allowed directories - set by the main module
let allowedDirectories: string[] = [];

// Function to set allowed directories from the main module
export function setAllowedDirectories(directories: string[]): void {
  allowedDirectories = [...directories];
}

// Function to get current allowed directories
export function getAllowedDirectories(): string[] {
  return [...allowedDirectories];
}

// Type definitions
interface FileInfo {
  size: number;
  created: Date;
  modified: Date;
  accessed: Date;
  isDirectory: boolean;
  isFile: boolean;
  permissions: string;
}

export interface SearchOptions {
  excludePatterns?: string[];
}

export interface SearchResult {
  path: string;
  isDirectory: boolean;
}

// Pure Utility Functions
export function formatSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  if (bytes <= 0) return '0 B';

  const i = Math.floor(Math.log(bytes) / Math.log(1024));

  if (i < 0 || i === 0) return `${bytes} ${units[0]}`;

  const unitIndex = Math.min(i, units.length - 1);
  return `${(bytes / Math.pow(1024, unitIndex)).toFixed(2)} ${units[unitIndex]}`;
}

export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, '\n');
}

export function createUnifiedDiff(originalContent: string, newContent: string, filepath: string = 'file'): string {
  // Ensure consistent line endings for diff
  const normalizedOriginal = normalizeLineEndings(originalContent);
  const normalizedNew = normalizeLineEndings(newContent);

  return createTwoFilesPatch(
    filepath,
    filepath,
    normalizedOriginal,
    normalizedNew,
    'original',
    'modified'
  );
}

// Helper function to resolve relative paths against allowed directories
function resolveRelativePathAgainstAllowedDirectories(relativePath: string): string {
  if (allowedDirectories.length === 0) {
    // Fallback to process.cwd() if no allowed directories are set
    return path.resolve(process.cwd(), relativePath);
  }

  // Try to resolve relative path against each allowed directory
  for (const allowedDir of allowedDirectories) {
    const candidate = path.resolve(allowedDir, relativePath);
    const normalizedCandidate = normalizePath(candidate);

    // Check if the resulting path lies within any allowed directory
    if (isPathWithinAllowedDirectories(normalizedCandidate, allowedDirectories)) {
      return candidate;
    }
  }

  // If no valid resolution found, use the first allowed directory as base
  // This provides a consistent fallback behavior
  return path.resolve(allowedDirectories[0], relativePath);
}

// Security & Validation Functions
async function resolveUnicodeEquivalentPath(absolutePath: string): Promise<string> {
  const allowedDirectory = [...allowedDirectories]
    .sort((left, right) => right.length - left.length)
    .find(directory => isPathWithinAllowedDirectories(normalizePath(absolutePath), [directory]));

  if (!allowedDirectory) {
    return absolutePath;
  }

  let currentPath = await fs.realpath(allowedDirectory);
  const relativeParts = path.relative(allowedDirectory, absolutePath).split(path.sep).filter(Boolean);

  for (let index = 0; index < relativeParts.length; index++) {
    const requestedPart = relativeParts[index];
    const entries = (await fs.readdir(currentPath)) ?? [];
    const exactMatch = entries.find(entry => entry === requestedPart);
    const equivalentMatches = exactMatch
      ? [exactMatch]
      : entries.filter(entry => entry.normalize('NFC') === requestedPart.normalize('NFC'));

    if (equivalentMatches.length > 1) {
      throw new Error(`Ambiguous Unicode path component: ${requestedPart}`);
    }

    if (equivalentMatches.length === 0) {
      // Nothing below this point exists yet, so there are no symlinks left to
      // resolve. currentPath is already realpath'd and inside an allowed
      // directory; append the missing tail so create_directory can mkdir -p it.
      return path.join(currentPath, ...relativeParts.slice(index));
    }

    currentPath = await fs.realpath(path.join(currentPath, equivalentMatches[0]));
    if (!isPathWithinAllowedDirectories(normalizePath(currentPath), allowedDirectories)) {
      throw new Error(`Access denied - symlink target outside allowed directories: ${currentPath} not in ${allowedDirectories.join(', ')}`);
    }
  }

  return currentPath;
}

export async function validatePath(requestedPath: string): Promise<string> {
  const expandedPath = expandHome(requestedPath);
  // Do not silently reinterpret a Windows drive path as a relative POSIX path.
  // This would create a literal filename such as `C:\\Users\\...` inside the
  // allowed root and report success for the wrong location.
  if (process.platform !== 'win32' && /^(?:[A-Za-z]:)(?:[\\/]|$)/.test(expandedPath)) {
    throw new Error(`Access denied - Windows-style path received on a POSIX host: ${requestedPath}`);
  }
  const absolute = path.isAbsolute(expandedPath)
    ? path.resolve(expandedPath)
    : resolveRelativePathAgainstAllowedDirectories(expandedPath);

  const normalizedRequested = normalizePath(absolute);

  // Security: Check if path is within allowed directories before any file operations
  const isAllowed = isPathWithinAllowedDirectories(normalizedRequested, allowedDirectories);
  if (!isAllowed) {
    throw new Error(`Access denied - path outside allowed directories: ${absolute} not in ${allowedDirectories.join(', ')}`);
  }

  // Security: Handle symlinks by checking their real path to prevent symlink attacks
  // This prevents attackers from creating symlinks that point outside allowed directories
  try {
    const realPath = await fs.realpath(absolute);
    const normalizedReal = normalizePath(realPath);
    if (!isPathWithinAllowedDirectories(normalizedReal, allowedDirectories)) {
      throw new Error(`Access denied - symlink target outside allowed directories: ${realPath} not in ${allowedDirectories.join(', ')}`);
    }
    return realPath;
  } catch (error) {
    // Security: For new files that don't exist yet, verify parent directory
    // This ensures we can't create files in unauthorized locations
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      try {
        return await resolveUnicodeEquivalentPath(absolute);
      } catch (resolutionError) {
        if ((resolutionError as NodeJS.ErrnoException).code === 'ENOENT') {
          throw new Error(`Parent directory does not exist: ${path.dirname(absolute)}`, { cause: resolutionError });
        }
        throw resolutionError;
      }
    }
    throw error;
  }
}


// File Operations
export async function getFileStats(filePath: string): Promise<FileInfo> {
  const stats = await fs.stat(filePath);
  return {
    size: stats.size,
    created: stats.birthtime,
    modified: stats.mtime,
    accessed: stats.atime,
    isDirectory: stats.isDirectory(),
    isFile: stats.isFile(),
    permissions: stats.mode.toString(8).slice(-3),
  };
}

export async function readFileContent(filePath: string, encoding: string = 'utf-8'): Promise<string> {
  return await fs.readFile(filePath, encoding as BufferEncoding);
}

export interface FileReadResult extends Record<string, unknown> {
  fileSize: number;
  totalLines: number;
  lineEnding?: '\r' | '\n' | '\r\n' | 'Mixed';
  truncatedAt?: {
    line: number;
    col: number;
    lineLength: number;
  };
  next?: {
    startLine: number;
    startCol: number;
  };
  note?: string;
  lines: string[];
}

export async function readFile(
  filePath: string,
  options: { startLine?: number; endLine?: number, startCol?: number; maxSize?: number } = {}
): Promise<FileReadResult> {
  const { startLine = 1, endLine, startCol, maxSize = 25000 } = options;
  if (endLine && endLine < startLine)
    throw new Error("endLine must be greater than or equal to startLine");

  const fileHandle = await fs.open(filePath, 'r');
  try {
    let pendingLine = '';
    const chunk = Buffer.alloc(65536); // 64KB buffer
    const decoder = new TextDecoder();
    let offset = 0;
    let lineCount = 1;
    let lineEnding: '\r' | '\n' | '\r\n' | 'Mixed' | undefined;
    let textLength = 0;
    let truncatedAt: Record<string, number> | undefined;
    let truncated = false;
    const notes = [];
    const lines = [];

    // Read chunks and count lines until we have enough or reach EOF
    let lineLength = 0;
    while (true) {
      const result = await fileHandle.read(chunk, 0, chunk.length, offset);
      if (result.bytesRead === 0) break; // End of file
      const bytes = chunk.subarray(0, result.bytesRead);
      if (!offset) {
        const nullPos = bytes.indexOf(0);
        if (nullPos !== -1)
          notes.push(`The file appears to be binary (NUL byte found at offset ${nullPos}); the text may be garbled - use read_media_file for images or audio.`);
      }
      const text = decoder.decode(bytes);

      let chunkLineCount = 0;
      let firstLineBreakPos, lastLineBreakPos;
      for (let i = 0; i < text.length; i++)
        if (text[i] === '\n' && text[i - 1] !== '\r' || text[i] === '\r') {
          chunkLineCount++;
          if (firstLineBreakPos === undefined)
            firstLineBreakPos = i;
          lastLineBreakPos = i;
        }
      let remainingText;
      if (chunkLineCount) {
        if (lineCount + chunkLineCount > startLine && (!endLine || lineCount <= endLine) && textLength < maxSize) {
          const completeLines = (pendingLine + text.slice(0, lastLineBreakPos)).split(/(\r\n|\r|\n)/);
          for (let i = 0; i < completeLines.length; i++) {
            if (i & 1) {
              if (lineEnding !== 'Mixed')
                if (lineEnding) {
                  if (completeLines[i] !== lineEnding)
                    lineEnding = 'Mixed';
                } else
                  lineEnding = completeLines[i] as '\r' | '\n' | '\r\n';
            } else {
              let line = completeLines[i];
              if (lineCount >= startLine && (!endLine || lineCount <= endLine) && textLength < maxSize) {
                lineLength = line.length;
                let colOffset;
                if (lineCount === startLine && startCol) {
                  line = line.slice(startCol);
                  colOffset = startCol;
                } else
                  colOffset = 0;
                if (textLength + line.length > maxSize) {
                  line = line.slice(0, maxSize - textLength);
                  truncatedAt = {
                    line: lineCount,
                    col: colOffset + line.length,
                    lineLength,
                    nextLine: lineCount,
                    nextCol: colOffset + line.length,
                  };
                  truncated = true;
                } else if (textLength + line.length === maxSize) {
                  truncatedAt = {
                    line: lineCount,
                    col: colOffset + line.length,
                    lineLength,
                    nextLine: lineCount + 1,
                    nextCol: 0,
                  };
                  truncated = true;
                }
                lines.push(line);
                textLength += line.length;
              }
              lineCount++;
            }
          }
        } else {
          if (textLength >= maxSize && !truncated) {
            lineLength += firstLineBreakPos!;
            if (truncatedAt)
              truncatedAt.lineLength = lineLength;
            else {
              let col = pendingLine.length;
              if (lineCount === startLine && startCol)
                col += startCol;
              truncatedAt = {
                line: lineCount,
                col,
                lineLength,
              };
              if (firstLineBreakPos) {
                truncatedAt.nextLine = lineCount;
                truncatedAt.nextCol = col;
              } else {
                truncatedAt.nextLine = lineCount + 1;
                truncatedAt.nextCol = 0;
              }
            }
            truncated = true;
          }
          lineCount += chunkLineCount;
        }
        remainingText = text.slice(lastLineBreakPos! + 1).replace('\n', '');
        lineLength = remainingText.length;
      } else {
        remainingText = text;
        lineLength += text.length;
      }

      let colOffset;
      if (lineCount === startLine && startCol)
        colOffset = startCol;
      else
        colOffset = 0;
      if (lineCount >= startLine && (!endLine || lineCount <= endLine) && !truncatedAt) {
        if (chunkLineCount)
          pendingLine = remainingText;
        else
          pendingLine += remainingText;
        textLength += remainingText.length;
        if (textLength > maxSize + colOffset) {
          pendingLine = pendingLine.slice(colOffset, maxSize + colOffset - textLength);
          lines.push(pendingLine);
          truncatedAt = {
            line: lineCount,
            col: colOffset + pendingLine.length,
            nextLine: lineCount,
            nextCol: colOffset + pendingLine.length,
          };
        }
      }
      offset += result.bytesRead;
    }

    if (truncatedAt) {
      if (!truncated)
        truncatedAt.lineLength = lineLength;
    } else if (lineCount >= startLine && (!endLine || lineCount <= endLine)) {
      // If there is leftover content and we still need lines, add it
      if (lineCount === startLine && startCol)
        lines.push(pendingLine.slice(startCol));
      else
        lines.push(pendingLine);
    }

    const result: FileReadResult = {
      fileSize: offset,
      totalLines: lineCount,
      lines
    };
    if (lineEnding)
      result.lineEnding = lineEnding;
    if (truncatedAt) {
      result.truncatedAt = {
        line: truncatedAt.line,
        col: truncatedAt.col,
        lineLength: truncatedAt.lineLength!
      };
      result.next = {
        startLine: truncatedAt.nextLine,
        startCol: truncatedAt.nextCol
      };
    }
    if (startLine > lineCount)
      notes.push(`startLine (${startLine}) is greater than totalLines (${lineCount}).`);
    if (notes.length)
      result.note = notes.join('\n');
    return result;
  } finally {
    await fileHandle.close();
  }
}

export interface FileEditResult {
  modified: {
    type: '+' | '-';
    line: number;
    text: string;
  }[];
  note?: string;
}

export async function editFile(
  filePath: string,
  edits: { line: number, delete?: boolean, col?: number | 'end', text?: string, deleteText?: string | number | boolean }[],
  dryRun?: boolean
): Promise<FileEditResult> {
  const origStats = await fs.stat(filePath);
  if (!origStats.isFile())
    throw new Error(`File (${filePath}) does not exist or is not a file`);
  const editMap = new Map(edits.map(e => [e.line, e]));
  if (editMap.size !== edits.length)
    throw new Error(`Duplicate line numbers found in edits`);
  const fileHandle = await fs.open(filePath, 'r+');

  let outFileSuffix = 0;
  try {
    while (true) {
      await fs.access(`${filePath}${outFileSuffix}`, fs.constants.F_OK);
      outFileSuffix++;
    }
  } catch { }
  let outFileHandle;
  try {
    const chunk = Buffer.alloc(65536); // 64KB buffer
    const decoder = new TextDecoder();
    if (!dryRun)
      outFileHandle = await fs.open(`${filePath}${outFileSuffix}`, 'a');
    let pendingLine = '';
    let offset = 0;
    let srcLineCount = 1, distLineCount = 1;
    const notes = [];
    const modified: { type: '+' | '-', line: number, text: string }[] = [];

    const formatColAndDeleteCount = (lineLength: number, col?: number | 'end', deleteText?: string | number | boolean) => {
      if (col) {
        if (col === 'end')
          col = lineLength;
        else if (col > lineLength)
          throw new Error(`Edit column ${col} is out of bounds for line ${srcLineCount}`);
        else if (col < 0) {
          const oCol = col;
          col += lineLength;
          if (col < 0)
            throw new Error(`Edit column ${oCol} is out of bounds for line ${srcLineCount}`);
        }
      } else
        col = 0;
      if (deleteText) {
        if (deleteText === true)
          deleteText = Infinity;
        else if (typeof deleteText === 'number' && deleteText < 0) {
          const deleteCount = deleteText;
          deleteText += lineLength - col;
          if (deleteText < 0)
            throw new Error(`Edit delete text count ${deleteCount} is out of negative bound for line ${srcLineCount}`);
        }
      } else
        deleteText = 0;
      return { col, deleteText };
    };

    let hasChange = false;
    let maxEditLine = 0;
    let lastLineEnding;
    for (const lineNumber of editMap.keys()) {
      if (!hasChange && lineNumber === 1)
        hasChange = true;
      if (lineNumber > maxEditLine)
        maxEditLine = lineNumber;
    }
    while (true) {
      const result = await fileHandle.read(chunk, 0, chunk.length, offset);
      if (result.bytesRead === 0) break; // End of file
      const bytes = chunk.subarray(0, result.bytesRead);
      if (!offset) {
        const nullPos = bytes.indexOf(0);
        if (nullPos !== -1)
          notes.push(`The file appears to be binary (NUL byte found at offset ${nullPos}); the text may be garbled.`);
      }
      const text = decoder.decode(bytes);

      let chunkLineCount = 0;
      let end;
      for (let i = 0; i < text.length; i++)
        if (text[i] === '\n' || text[i] === '\r') {
          end = i + 1;
          if (text[i] === '\n' && text[i - 1] !== '\r' || text[i] === '\r')
            chunkLineCount++;
        }
      if (chunkLineCount) {
        hasChange = false;
        for (const lineNumber of editMap.keys())
          if (srcLineCount <= lineNumber && srcLineCount + chunkLineCount > lineNumber) {
            hasChange = true;
            break;
          }
        if (hasChange) {
          const completeLines = (pendingLine + text.slice(0, end)).split(/(\r\n|\n|\r)/);
          for (let i = 0; i < completeLines.length - 1; i += 2) {
            const line = completeLines[i];
            const lineEnding = completeLines[i + 1];
            const edit = editMap.get(srcLineCount);
            if (edit) {
              modified.push({ type: '-', line: srcLineCount, text: line });
              if (!edit.delete) {
                let newLine = '';
                const { col, deleteText } = formatColAndDeleteCount(line.length, edit.col, edit.deleteText);
                newLine = line.slice(0, col);
                if (edit.text)
                  newLine += edit.text;
                if (typeof deleteText === 'number')
                  newLine += line.slice(col + deleteText);
                else
                  newLine += line.slice(col).replace(deleteText, '');
                const lines = newLine.split(/(\r\n|\n|\r)/);
                for (let i = 0; i < lines.length; i += 2) {
                  if (
                    // If the text starts with \n and lastLineEnding is \r, they are combined to a line terminator
                    lastLineEnding === '\r' && !i && !lines[i] && lines[i + 1] === '\n' ||
                    // If the text ends with \r and lineEnding is \n, they are combined to a line terminator
                    lines[i - 1] === '\r' && i === lines.length - 1 && !lines[i] && lineEnding === '\n'
                  )
                    continue;
                  modified.push({ type: '+', line: distLineCount, text: lines[i] });
                  distLineCount++;
                }
                newLine += lineEnding;
                if (outFileHandle)
                  await outFileHandle.appendFile(newLine);
              }
            } else {
              distLineCount++;
              if (outFileHandle)
                await outFileHandle.appendFile(line + lineEnding);
            }
            srcLineCount++;
            lastLineEnding = lineEnding;
          }
          hasChange = false;
        } else {
          srcLineCount += chunkLineCount;
          distLineCount += chunkLineCount;
          lastLineEnding = text[end! - 1];
          if (outFileHandle)
            await outFileHandle.appendFile(text.slice(0, end));
        }
        for (const lineNumber of editMap.keys())
          if (srcLineCount === lineNumber) {
            hasChange = true;
            break;
          }
        pendingLine = text.slice(end);
        if (!hasChange) {
          if (outFileHandle)
            await outFileHandle.appendFile(pendingLine);
          pendingLine = '';
        }
      } else {
        if (hasChange)
          pendingLine += text;
        else if (outFileHandle)
          await outFileHandle.appendFile(bytes);
      }
      offset += result.bytesRead;
    }
    if (hasChange) {
      const edit = editMap.get(srcLineCount)!;
      modified.push({ type: '-', line: srcLineCount, text: pendingLine });
      if (!edit.delete) {
        let newLine = '';
        const { col, deleteText } = formatColAndDeleteCount(pendingLine.length, edit.col, edit.deleteText);
        newLine = pendingLine.slice(0, col);
        if (edit.text)
          newLine += edit.text;
        if (typeof deleteText === 'number')
          newLine += pendingLine.slice(col + deleteText);
        else
          newLine += pendingLine.slice(col).replace(deleteText, '');
        const lines = newLine.split(/(\r\n|\n|\r)/);
        for (let i = 0; i < lines.length; i += 2) {
          // If the text starts with \n and lastLineEnding is \r, they are combined to a line terminator
          if (lastLineEnding === '\r' && !i && !lines[i] && lines[i + 1] === '\n')
            continue;
          modified.push({ type: '+', line: distLineCount, text: lines[i] });
          distLineCount++;
        }
        if (outFileHandle)
          await outFileHandle.appendFile(newLine);
      }
    }
    if (maxEditLine > srcLineCount)
      notes.push(`Edit lines with line number greater than total lines (${srcLineCount}) are not processed.`);
    const output: FileEditResult = { modified };
    if (notes.length)
      output.note = notes.join('\n');

    await fileHandle.close();
    if (outFileHandle) {
      await outFileHandle.close();
      await fs.rename(filePath, `${filePath}.bak`);
      try {
        await fs.rename(`${filePath}${outFileSuffix}`, filePath);
        try {
          await fs.chmod(filePath, origStats.mode & 0o777);
        } catch { }
        try {
          await fs.rm(`${filePath}.bak`);
        } catch { }
      } catch (e) {
        await fs.rename(`${filePath}.bak`, filePath);
        throw e;
      }
    }
    return output;
  } finally {
    await fileHandle.close();
    if (outFileHandle) {
      await outFileHandle.close();
      await fs.rm(`${filePath}${outFileSuffix}`, { force: true });
    }
  }
}

export async function writeFileContent(filePath: string, content: string): Promise<void> {
  try {
    // Security: 'wx' flag ensures exclusive creation - fails if file/symlink exists,
    // preventing writes through pre-existing symlinks
    await fs.writeFile(filePath, content, { encoding: "utf-8", flag: 'wx' });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      // Security: Use atomic rename to prevent race conditions where symlinks
      // could be created between validation and write. Rename operations
      // replace the target file atomically and don't follow symlinks.
      const origStats = await fs.stat(filePath);
      const tempPath = `${filePath}.${randomBytes(16).toString('hex')}.tmp`;
      try {
        await fs.writeFile(tempPath, content, 'utf-8');
        await fs.rename(tempPath, filePath);
      } catch (renameError) {
        try {
          await fs.unlink(tempPath);
        } catch { }
        throw renameError;
      }
      // Restore original permission bits since the atomic rename replaces the
      // inode and the temp file has default (0644) permissions. Mask off the
      // file-type bits; POSIX leaves them unspecified for chmod. A chmod
      // failure must not fail the write, which has already succeeded.
      try {
        await fs.chmod(filePath, origStats.mode & 0o777);
      } catch { }
    } else {
      throw error;
    }
  }
}


export async function moveFile(sourcePath: string, destinationPath: string): Promise<void> {
  // The move_file tool contract (and README) state the operation fails if the
  // destination already exists. fs.rename would silently overwrite it, which is
  // a data-loss bug, so reject up front when anything - file, directory, or
  // symlink - occupies the target. lstat is used so an existing symlink at the
  // destination is detected rather than followed.
  try {
    await fs.lstat(destinationPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      await fs.rename(sourcePath, destinationPath);
      return;
    }
    throw error;
  }
  throw new Error(`Destination already exists: ${destinationPath}`);
}


// File Editing Functions
interface FileEdit {
  oldText: string;
  newText: string;
}

export async function applyFileEdits(
  filePath: string,
  edits: FileEdit[],
  dryRun: boolean = false
): Promise<string> {
  // Read file content and normalize line endings
  const content = normalizeLineEndings(await fs.readFile(filePath, 'utf-8'));

  // Apply edits sequentially
  let modifiedContent = content;
  for (const edit of edits) {
    const normalizedOld = normalizeLineEndings(edit.oldText);
    const normalizedNew = normalizeLineEndings(edit.newText);

    // If exact match exists, use it
    if (modifiedContent.includes(normalizedOld)) {
      modifiedContent = modifiedContent.replace(normalizedOld, () => normalizedNew);
      continue;
    }

    // Otherwise, try line-by-line matching with flexibility for whitespace
    const oldLines = normalizedOld.split('\n');
    const contentLines = modifiedContent.split('\n');
    let matchFound = false;

    for (let i = 0; i <= contentLines.length - oldLines.length; i++) {
      const potentialMatch = contentLines.slice(i, i + oldLines.length);

      // Compare lines with normalized whitespace
      const isMatch = oldLines.every((oldLine, j) => {
        const contentLine = potentialMatch[j];
        return oldLine.trim() === contentLine.trim();
      });

      if (isMatch) {
        // Preserve original indentation of first line
        const originalIndent = contentLines[i].match(/^\s*/)?.[0] || '';
        const newLines = normalizedNew.split('\n').map((line, j) => {
          if (j === 0) return originalIndent + line.trimStart();
          // For subsequent lines, try to preserve relative indentation
          const oldIndent = oldLines[j]?.match(/^\s*/)?.[0] || '';
          const newIndent = line.match(/^\s*/)?.[0] || '';
          if (oldIndent && newIndent) {
            const relativeIndent = newIndent.length - oldIndent.length;
            return originalIndent + ' '.repeat(Math.max(0, relativeIndent)) + line.trimStart();
          }
          return line;
        });

        contentLines.splice(i, oldLines.length, ...newLines);
        modifiedContent = contentLines.join('\n');
        matchFound = true;
        break;
      }
    }

    if (!matchFound) {
      throw new Error(`Could not find exact match for edit:\n${edit.oldText}`);
    }
  }

  // Create unified diff
  const diff = createUnifiedDiff(content, modifiedContent, filePath);

  // Format diff with appropriate number of backticks
  let numBackticks = 3;
  while (diff.includes('`'.repeat(numBackticks))) {
    numBackticks++;
  }
  const formattedDiff = `${'`'.repeat(numBackticks)}diff\n${diff}${'`'.repeat(numBackticks)}\n\n`;

  if (!dryRun) {
    // Security: Use atomic rename to prevent race conditions where symlinks
    // could be created between validation and write. Rename operations
    // replace the target file atomically and don't follow symlinks.
    const origStats = await fs.stat(filePath);
    const tempPath = `${filePath}.${randomBytes(16).toString('hex')}.tmp`;
    try {
      await fs.writeFile(tempPath, modifiedContent, 'utf-8');
      await fs.rename(tempPath, filePath);
    } catch (error) {
      try {
        await fs.unlink(tempPath);
      } catch { }
      throw error;
    }
    // Restore original permission bits since the atomic rename replaces the
    // inode and the temp file has default (0644) permissions. Mask off the
    // file-type bits; POSIX leaves them unspecified for chmod. A chmod
    // failure must not fail the write, which has already succeeded.
    try {
      await fs.chmod(filePath, origStats.mode & 0o777);
    } catch { }
  }

  return formattedDiff;
}

export async function searchFilesWithValidation(
  rootPath: string,
  pattern: string,
  options: SearchOptions = {}
): Promise<string[]> {
  const { excludePatterns = [] } = options;
  const results: string[] = [];

  async function search(currentPath: string) {
    const entries = await fs.readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      try {
        await validatePath(fullPath);

        const relativePath = path.relative(rootPath, fullPath);
        const shouldExclude = excludePatterns.some(excludePattern =>
          minimatch(relativePath, excludePattern, { dot: true })
        );

        if (shouldExclude) continue;

        // Use glob matching for the search pattern
        if (minimatch(relativePath, pattern, { dot: true })) {
          results.push(fullPath);
        }

        if (entry.isDirectory()) {
          await search(fullPath);
        }
      } catch {
        continue;
      }
    }
  }

  await search(rootPath);
  return results;
}
