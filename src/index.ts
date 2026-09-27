import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  RootsListChangedNotificationSchema,
  type Root,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "fs/promises";
import { createReadStream } from "fs";
import path from "path";
import { pathToFileURL } from "url";
import { z } from "zod";
import { minimatch } from "minimatch";
import { normalizePath, expandHome } from './path-utils.js';
import { getValidRootDirectories } from './roots-utils.js';
import {
  // Function imports
  formatSize,
  validatePath,
  getFileStats,
  readFile,
  readFileContent,
  writeFileContent,
  moveFile,
  searchFilesWithValidation,
  applyFileEdits,
  setAllowedDirectories,
} from './lib.js';

// Command line argument parsing
const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("Usage: file-system-mcp-server [allowed-directory] [additional-directories...]");
  console.error("Note: Allowed directories can be provided via:");
  console.error("  1. Command-line arguments (shown above)");
  console.error("  2. MCP roots protocol (if client supports it)");
  console.error("At least one directory must be provided by EITHER method for the server to operate.");
}

// Store allowed directories in normalized and resolved form
// We store BOTH the original path AND the resolved path to handle symlinks correctly
// This fixes the macOS /tmp -> /private/tmp symlink issue where users specify /tmp
// but the resolved path is /private/tmp
let allowedDirectories = (await Promise.all(
  args.map(async (dir) => {
    const expanded = expandHome(dir);
    const absolute = path.resolve(expanded);
    const normalizedOriginal = normalizePath(absolute);
    try {
      // Security: Resolve symlinks in allowed directories during startup
      // This ensures we know the real paths and can validate against them later
      const resolved = await fs.realpath(absolute);
      const normalizedResolved = normalizePath(resolved);
      // Return both original and resolved paths if they differ
      // This allows matching against either /tmp or /private/tmp on macOS
      if (normalizedOriginal !== normalizedResolved) {
        return [normalizedOriginal, normalizedResolved];
      }
      return [normalizedResolved];
    } catch {
      // If we can't resolve (doesn't exist), use the normalized absolute path
      // This allows configuring allowed dirs that will be created later
      return [normalizedOriginal];
    }
  })
)).flat();

// Filter to only accessible directories, warn about inaccessible ones
const accessibleDirectories: string[] = [];
for (const dir of allowedDirectories) {
  try {
    const stats = await fs.stat(dir);
    if (stats.isDirectory()) {
      accessibleDirectories.push(dir);
    } else {
      console.error(`Warning: ${dir} is not a directory, skipping`);
    }
  } catch {
    console.error(`Warning: Cannot access directory ${dir}, skipping`);
  }
}

// Exit only if ALL paths are inaccessible (and some were specified)
if (accessibleDirectories.length === 0 && allowedDirectories.length > 0) {
  console.error("Error: None of the specified directories are accessible");
  process.exit(1);
}

allowedDirectories = accessibleDirectories;

// Initialize the global allowedDirectories in lib.ts
setAllowedDirectories(allowedDirectories);

// Schema definitions
const ReadTextFileArgsSchema = z.object({
  path: z.string().describe(
    'Path of the file to read. Absolute paths are preferred; relative paths are resolved ' +
    'against the allowed directories. Must resolve inside an allowed directory.'
  ),
  startLine: z.number().int().min(1, 'startLine must be >= 1 (lines are 1-indexed)')
    .optional().describe('First line to return (1-indexed). Defaults to 1.'),
  endLine: z.number().int().min(1, 'endLine must be >= 1 (lines are 1-indexed)')
    .optional().describe('Last line to return, inclusive (1-indexed). Defaults to end of file.'),
  startCol: z.number().int().min(0, 'startCol must be >= 0')
    .optional().describe('0-indexed UTF-16 offset applied to startLine only. Defaults to 0.'),
  maxSize: z.number().int().min(0, 'maxSize must be >= 0; omit it to use the 25000 default')
    .max(25000, 'maxSize must be <= 25000')
    .optional().describe('Maximum UTF-16 units of line content to return (0-25000, default 25000); line terminators are not counted.')
});

const ReadMediaFileArgsSchema = z.object({
  path: z.string()
});

const ReadMultipleFilesArgsSchema = z.object({
  paths: z
    .array(z.string())
    .min(1, "At least one file path must be provided")
    .describe("Array of file paths to read. Each path must be a string pointing to a valid file within allowed directories."),
});

const WriteFileArgsSchema = z.object({
  path: z.string(),
  content: z.string(),
});

const EditFileArgsSchema = z.object({
  path: z.string(),
  edits: z.array(z.object({
    oldText: z.string().describe('Text to search for - must match exactly'),
    newText: z.string().describe('Text to replace with')
  })),
  dryRun: z.boolean().default(false).describe('Preview changes using git-style diff format')
});

const CreateDirectoryArgsSchema = z.object({
  path: z.string(),
});

const ListDirectoryArgsSchema = z.object({
  path: z.string(),
});

const ListDirectoryWithSizesArgsSchema = z.object({
  path: z.string(),
  sortBy: z.enum(['name', 'size']).optional().default('name').describe('Sort entries by name or size'),
});

const DirectoryTreeArgsSchema = z.object({
  path: z.string(),
  excludePatterns: z.array(z.string()).optional().default([])
});

const MoveFileArgsSchema = z.object({
  source: z.string(),
  destination: z.string(),
});

const SearchFilesArgsSchema = z.object({
  path: z.string(),
  pattern: z.string(),
  excludePatterns: z.array(z.string()).optional().default([])
});

const GetFileInfoArgsSchema = z.object({
  path: z.string(),
});

// Server setup
const server = new McpServer(
  {
    name: "file-system-mcp-server",
    version: "0.6.3",
  },
  {
    // Shared conventions for every tool, stated once instead of repeating them in every
    // tool description. Clients that surface `instructions` pass this to the model.
    instructions:
      "All tools operate only inside the configured allowed directories " +
      "(see list_allowed_directories) and report failures as tool errors. Prefer absolute " +
      "paths; relative paths are resolved against the allowed directories.",
  }
);

// Reads a file as a stream of buffers, concatenates them, and then encodes
// the result to a Base64 string. This is a memory-efficient way to handle
// binary data from a stream before the final encoding.
async function readFileAsBase64Stream(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    const chunks: Buffer[] = [];
    stream.on('data', (chunk) => {
      chunks.push(chunk as Buffer);
    });
    stream.on('end', () => {
      const finalBuffer = Buffer.concat(chunks);
      resolve(finalBuffer.toString('base64'));
    });
    stream.on('error', (err) => reject(err));
  });
}

// Tool registrations

server.registerTool(
  "read_text_file",
  {
    title: "Read Text File",
    description: [
      "Read one text file inside the allowed directories and return its contents as JSON. Use",
      "read_multiple_files for several files at once, and read_media_file for images or audio.",
      "",
      "Result (a JSON object):",
      "- fileSize: size of the file in bytes.",
      "- totalLines: lines in the whole file; an empty file counts 1 empty line, a trailing",
      "  newline adds a trailing empty line.",
      "- lineEnding: \"LF\", \"CRLF\" or \"Mixed\", from the returned range only; absent if none seen.",
      "- lines: an OBJECT, not an array - ABSOLUTE 1-indexed line numbers as decimal string keys",
      "  mapped to each line's text without its terminator. Empty (zero-length) lines are omitted",
      "  and their absolute 1-indexed numbers listed in emptyLines instead, so concatenating",
      "  lines cannot rebuild the file; in the returned range a missing line number therefore",
      "  means an empty line, and lines itself is omitted when nothing was recorded.",
      "- truncatedAt { line, col, lineLength } plus next { startLine, startCol }: truncatedAt is",
      "  set when maxSize cut the payload short (1-indexed line, 0-indexed column of the stop, full",
      "  length of that line); pass next straight back into the next call to resume exactly",
      "  there, repeating until next is absent.",
      "- note: set when the result needs explaining, e.g. startLine past the end of the file, or",
      "  a NUL byte in the first 64 KB (probably binary; bytes are always decoded as UTF-8 and may",
      "  be garbled - use read_media_file).",
      "",
      "Param note: maxSize (1-25000, default 25000) counts UTF-16 units of line content without",
      "terminators and only caps the payload - the file is still scanned to EOF, so totalLines is",
      "exact. Other params are documented by inputSchema; prefer ranges over reading huge files.",
      "",
      "Errors come back as tool errors: path outside the allowed directories, missing, a directory",
      "(use list_directory for directories), or endLine < startLine."
    ].join('\n'),
    inputSchema: ReadTextFileArgsSchema,
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ReadTextFileArgsSchema>) => {
    const validPath = await validatePath(args.path);

    if (args.startLine && args.endLine && args.endLine < args.startLine)
      throw new Error("endLine must be greater than or equal to startLine");

    const result = await readFile(validPath, args);

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result) }]
    };
  }
);

server.registerTool(
  "read_media_file",
  {
    title: "Read Media File",
    description:
      "Read a file and return it as a base64-encoded content block with its MIME type. " +
      "Image and audio files are returned as image/audio content; any other file type is " +
      "returned as an embedded resource.",
    inputSchema: ReadMediaFileArgsSchema,
    outputSchema: {
      content: z.array(z.union([
        z.object({
          type: z.enum(["image", "audio"]),
          data: z.string(),
          mimeType: z.string()
        }),
        z.object({
          type: z.literal("resource"),
          resource: z.object({
            uri: z.string(),
            // Optional, matching the SDK's BlobResourceContents shape (the handler always sets it).
            mimeType: z.string().optional(),
            blob: z.string()
          })
        })
      ]))
    },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ReadMediaFileArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const extension = path.extname(validPath).toLowerCase();
    const mimeTypes: Record<string, string> = {
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".gif": "image/gif",
      ".webp": "image/webp",
      ".bmp": "image/bmp",
      ".svg": "image/svg+xml",
      ".mp3": "audio/mpeg",
      ".wav": "audio/wav",
      ".ogg": "audio/ogg",
      ".flac": "audio/flac",
    };
    const mimeType = mimeTypes[extension] || "application/octet-stream";
    const data = await readFileAsBase64Stream(validPath);

    // Map the MIME type to a valid MCP content block. The spec only allows
    // text, image, audio, resource_link, and resource — so non-image/audio
    // binaries are returned as an embedded resource (NOT type:"blob", which the
    // SDK content-block union rejects on schema validation).
    const contentItem =
      mimeType.startsWith("image/")
        ? { type: "image" as const, data, mimeType }
        : mimeType.startsWith("audio/")
          ? { type: "audio" as const, data, mimeType }
          : {
            type: "resource" as const,
            resource: { uri: pathToFileURL(validPath).href, mimeType, blob: data }
          };
    return {
      content: [contentItem],
      structuredContent: { content: [contentItem] }
    };
  }
);

server.registerTool(
  "read_multiple_files",
  {
    title: "Read Multiple Files",
    description:
      "Read the contents of multiple files simultaneously. This is more " +
      "efficient than reading files one by one when you need to analyze " +
      "or compare multiple files. Each file's content is returned with its " +
      "path as a reference. Failed reads for individual files won't stop " +
      "the entire operation.",
    inputSchema: ReadMultipleFilesArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ReadMultipleFilesArgsSchema>) => {
    const results = await Promise.all(
      args.paths.map(async (filePath: string) => {
        try {
          const validPath = await validatePath(filePath);
          const content = await readFileContent(validPath);
          return `${filePath}:\n${content}\n`;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return `${filePath}: Error - ${errorMessage}`;
        }
      }),
    );
    const text = results.join("\n---\n");
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "write_file",
  {
    title: "Write File",
    description:
      "Create a new file or completely overwrite an existing file with new content. " +
      "Use with caution as it will overwrite existing files without warning. " +
      "Handles text content with proper encoding.",
    inputSchema: WriteFileArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof WriteFileArgsSchema>) => {
    const validPath = await validatePath(args.path);
    await writeFileContent(validPath, args.content);
    const text = `Successfully wrote to ${args.path}`;
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "edit_file",
  {
    title: "Edit File",
    description:
      "Make line-based edits to a text file. Each edit replaces exact line sequences " +
      "with new content. Returns a git-style diff showing the changes made.",
    inputSchema: EditFileArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof EditFileArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const result = await applyFileEdits(validPath, args.edits, args.dryRun);
    return {
      content: [{ type: "text" as const, text: result }],
      structuredContent: { content: result }
    };
  }
);

server.registerTool(
  "create_directory",
  {
    title: "Create Directory",
    description:
      "Create a new directory or ensure a directory exists. Can create multiple " +
      "nested directories in one operation. If the directory already exists, " +
      "this operation will succeed silently. Perfect for setting up directory " +
      "structures for projects or ensuring required paths exist.",
    inputSchema: CreateDirectoryArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: false, openWorldHint: false }
  },
  async (args: z.infer<typeof CreateDirectoryArgsSchema>) => {
    const validPath = await validatePath(args.path);
    await fs.mkdir(validPath, { recursive: true });
    const text = `Successfully created directory ${args.path}`;
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "list_directory",
  {
    title: "List Directory",
    description:
      "Get a detailed listing of all files and directories in a specified path. " +
      "Results clearly distinguish between files and directories with [FILE] and [DIR] " +
      "prefixes. This tool is essential for understanding directory structure and " +
      "finding specific files within a directory.",
    inputSchema: ListDirectoryArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ListDirectoryArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const entries = await fs.readdir(validPath, { withFileTypes: true });
    const formatted = entries
      .map((entry) => `${entry.isDirectory() ? "[DIR]" : "[FILE]"} ${entry.name}`)
      .join("\n");
    return {
      content: [{ type: "text" as const, text: formatted }],
      structuredContent: { content: formatted }
    };
  }
);

server.registerTool(
  "list_directory_with_sizes",
  {
    title: "List Directory with Sizes",
    description:
      "Get a detailed listing of all files and directories in a specified path, including sizes. " +
      "Results clearly distinguish between files and directories with [FILE] and [DIR] " +
      "prefixes. This tool is useful for understanding directory structure and " +
      "finding specific files within a directory.",
    inputSchema: ListDirectoryWithSizesArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ListDirectoryWithSizesArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const entries = await fs.readdir(validPath, { withFileTypes: true });

    // Get detailed information for each entry
    const detailedEntries = await Promise.all(
      entries.map(async (entry) => {
        const entryPath = path.join(validPath, entry.name);
        try {
          const stats = await fs.stat(entryPath);
          return {
            name: entry.name,
            isDirectory: entry.isDirectory(),
            size: stats.size,
            mtime: stats.mtime
          };
        } catch {
          return {
            name: entry.name,
            isDirectory: entry.isDirectory(),
            size: 0,
            mtime: new Date(0)
          };
        }
      })
    );

    // Sort entries based on sortBy parameter
    const sortedEntries = [...detailedEntries].sort((a, b) => {
      if (args.sortBy === 'size') {
        return b.size - a.size; // Descending by size
      }
      // Default sort by name
      return a.name.localeCompare(b.name);
    });

    // Format the output
    const formattedEntries = sortedEntries.map(entry =>
      `${entry.isDirectory ? "[DIR]" : "[FILE]"} ${entry.name.padEnd(30)} ${entry.isDirectory ? "" : formatSize(entry.size).padStart(10)
      }`
    );

    // Add summary
    const totalFiles = detailedEntries.filter(e => !e.isDirectory).length;
    const totalDirs = detailedEntries.filter(e => e.isDirectory).length;
    const totalSize = detailedEntries.reduce((sum, entry) => sum + (entry.isDirectory ? 0 : entry.size), 0);

    const summary = [
      "",
      `Total: ${totalFiles} files, ${totalDirs} directories`,
      `Combined size: ${formatSize(totalSize)}`
    ];

    const text = [...formattedEntries, ...summary].join("\n");
    const contentBlock = { type: "text" as const, text };
    return {
      content: [contentBlock],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "directory_tree",
  {
    title: "Directory Tree",
    description:
      "Get a recursive tree view of files and directories as a JSON structure. " +
      "Each entry includes 'name', 'type' (file/directory), and 'children' for directories. " +
      "Files have no children array, while directories always have a children array (which may be empty). " +
      "The output is formatted with 2-space indentation for readability.",
    inputSchema: DirectoryTreeArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof DirectoryTreeArgsSchema>) => {
    interface TreeEntry {
      name: string;
      type: 'file' | 'directory';
      children?: TreeEntry[];
    }
    const rootPath = args.path;

    async function buildTree(currentPath: string, excludePatterns: string[] = []): Promise<TreeEntry[]> {
      const validPath = await validatePath(currentPath);
      const entries = await fs.readdir(validPath, { withFileTypes: true });
      const result: TreeEntry[] = [];

      for (const entry of entries) {
        const relativePath = path.relative(rootPath, path.join(currentPath, entry.name));
        const shouldExclude = excludePatterns.some(pattern => {
          if (pattern.includes('*')) {
            return minimatch(relativePath, pattern, { dot: true });
          }
          // For files: match exact name or as part of path
          // For directories: match as directory path
          return minimatch(relativePath, pattern, { dot: true }) ||
            minimatch(relativePath, `**/${pattern}`, { dot: true }) ||
            minimatch(relativePath, `**/${pattern}/**`, { dot: true });
        });
        if (shouldExclude)
          continue;

        const entryData: TreeEntry = {
          name: entry.name,
          type: entry.isDirectory() ? 'directory' : 'file'
        };

        if (entry.isDirectory()) {
          const subPath = path.join(currentPath, entry.name);
          entryData.children = await buildTree(subPath, excludePatterns);
        }

        result.push(entryData);
      }

      return result;
    }

    const treeData = await buildTree(rootPath, args.excludePatterns);
    const text = JSON.stringify(treeData, null, 2);
    const contentBlock = { type: "text" as const, text };
    return {
      content: [contentBlock],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "move_file",
  {
    title: "Move File",
    description:
      "Move or rename files and directories. Can move files between directories " +
      "and rename them in a single operation. If the destination exists, the " +
      "operation will fail. Works across different directories and can be used " +
      "for simple renaming within the same directory.",
    inputSchema: MoveFileArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof MoveFileArgsSchema>) => {
    const validSourcePath = await validatePath(args.source);
    const validDestPath = await validatePath(args.destination);
    await moveFile(validSourcePath, validDestPath);
    const text = `Successfully moved ${args.source} to ${args.destination}`;
    const contentBlock = { type: "text" as const, text };
    return {
      content: [contentBlock],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "search_files",
  {
    title: "Search Files",
    description:
      "Recursively search for files and directories matching a pattern. " +
      "The patterns should be glob-style patterns that match paths relative to the working directory. " +
      "Use pattern like '*.ext' to match files in current directory, and '**/*.ext' to match files in all subdirectories. " +
      "Returns full paths to all matching items. Great for finding files when you don't know their exact location.",
    inputSchema: SearchFilesArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof SearchFilesArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const results = await searchFilesWithValidation(validPath, args.pattern, allowedDirectories, { excludePatterns: args.excludePatterns });
    const text = results.length > 0 ? results.join("\n") : "No matches found";
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "get_file_info",
  {
    title: "Get File Info",
    description:
      "Retrieve detailed metadata about a file or directory. Returns comprehensive " +
      "information including size, creation time, last modified time, permissions, " +
      "and type. This tool is perfect for understanding file characteristics " +
      "without reading the actual content.",
    inputSchema: GetFileInfoArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof GetFileInfoArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const info = await getFileStats(validPath);
    const text = Object.entries(info)
      .map(([key, value]) => `${key}: ${value}`)
      .join("\n");
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

server.registerTool(
  "list_allowed_directories",
  {
    title: "List Allowed Directories",
    description:
      "Returns the list of directories that this server is allowed to access. " +
      "Subdirectories within these allowed directories are also accessible. " +
      "Use this to understand which directories and their nested paths are available " +
      "before trying to access files.",
    inputSchema: {},
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async () => {
    const text = `Allowed directories:\n${allowedDirectories.join('\n')}`;
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

// Updates allowed directories based on MCP client roots
async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
  const validatedRootDirs = await getValidRootDirectories(requestedRoots);
  if (validatedRootDirs.length > 0) {
    allowedDirectories = [...validatedRootDirs];
    setAllowedDirectories(allowedDirectories); // Update the global state in lib.ts
    console.error(`Updated allowed directories from MCP roots: ${validatedRootDirs.length} valid directories`);
  } else {
    console.error("No valid root directories provided by client");
  }
}

// Handles dynamic roots updates during runtime, when client sends "roots/list_changed" notification, server fetches the updated roots and replaces all allowed directories with the new roots.
server.server.setNotificationHandler(RootsListChangedNotificationSchema, async () => {
  try {
    // Request the updated roots list from the client
    const response = await server.server.listRoots();
    if (response && 'roots' in response) {
      await updateAllowedDirectoriesFromRoots(response.roots);
    }
  } catch (error) {
    console.error("Failed to request roots from client:", error instanceof Error ? error.message : String(error));
  }
});

// Handles post-initialization setup, specifically checking for and fetching MCP roots.
server.server.oninitialized = async () => {
  const clientCapabilities = server.server.getClientCapabilities();

  if (clientCapabilities?.roots) {
    try {
      const response = await server.server.listRoots();
      if (response && 'roots' in response) {
        await updateAllowedDirectoriesFromRoots(response.roots);
      } else {
        console.error("Client returned no roots set, keeping current settings");
      }
    } catch (error) {
      console.error("Failed to request initial roots from client:", error instanceof Error ? error.message : String(error));
    }
  } else {
    if (allowedDirectories.length > 0) {
      console.error("Client does not support MCP Roots, using allowed directories set from server args:", allowedDirectories);
    } else {
      throw new Error(`Server cannot operate: No allowed directories available. Server was started without command-line directories and client either does not support MCP roots protocol or provided empty roots. Please either: 1) Start server with directory arguments, or 2) Use a client that supports MCP roots protocol and provides valid root directories.`);
    }
  }
};

// Start server
async function runServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log("Secure File System MCP Filesystem Server running on stdio");
  if (allowedDirectories.length === 0) {
    console.log("Started without allowed directories - waiting for client to provide roots via MCP protocol");
  }
}

runServer().catch((error) => {
  console.error("Fatal error running server:", error);
  process.exit(1);
});
