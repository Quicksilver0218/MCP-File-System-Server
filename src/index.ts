import { McpServer } from "@modelcontextprotocol/sdk/server/mcp";
import { RegisteredTool, ToolCallback } from "@modelcontextprotocol/sdk/server/mcp";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";
import {
  ErrorCode,
  McpError,
  RootsListChangedNotificationSchema,
  ToolAnnotations,
  type Root,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "fs/promises";
import { createReadStream } from "fs";
import path from "path";
import { pathToFileURL } from "url";
import { z } from "zod";
import { minimatch } from "minimatch";
import { normalizePath, expandHome } from './path-utils';
import { getValidRootDirectories } from './roots-utils';
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
  editFile,
  searchText,
  setForbiddenDirectories,
} from './lib.js';
import { ZodRawShapeCompat, AnySchema } from "@modelcontextprotocol/sdk/server/zod-compat";

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
let allowedDirectories: string[] = [];
let forbiddenDirectories: string[] = [];
await Promise.all(
  args.map(async (arg) => {
    let directories;
    let dir;
    if (arg.startsWith("+")) {
      directories = allowedDirectories;
      dir = arg.slice(1);
    } else if (arg.startsWith("-")) {
      directories = forbiddenDirectories;
      dir = arg.slice(1);
    } else {
      directories = allowedDirectories;
      dir = arg;
    }
    const expanded = expandHome(dir);
    const absolute = path.resolve(expanded);
    const normalizedOriginal = normalizePath(absolute);
    if (!path.isAbsolute(normalizedOriginal))
      throw new Error('Directories must be absolute paths after normalization');
    directories.push(normalizedOriginal);
    try {
      // Security: Resolve symlinks in allowed directories during startup
      // This ensures we know the real paths and can validate against them later
      const resolved = await fs.realpath(absolute);
      const normalizedResolved = normalizePath(resolved);
      if (!path.isAbsolute(normalizedResolved))
        throw new Error('Directories must be absolute paths after normalization');
      // Return both original and resolved paths if they differ
      // This allows matching against either /tmp or /private/tmp on macOS
      if (normalizedOriginal !== normalizedResolved)
        directories.push(normalizedResolved);
    } catch { }
  })
);

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
setForbiddenDirectories(forbiddenDirectories);

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
    .optional().describe('Maximum UTF-16 units of line content to return (0-25000, default 25000)')
});

const EditTextFileArgsSchema = z.object({
  path: z.string().describe(
    'Path of the file to edit. Absolute paths are preferred; relative paths are resolved ' +
    'against the allowed directories. Must resolve inside an allowed directory.'
  ),
  edits: z.array(z.object({
    line: z.number().int().min(1, 'line must be >= 1 (lines are 1-indexed)').describe('1-indexed line number to edit'),
    delete: z.boolean().optional().describe('If true, delete the line and ignore col, text and deleteText.'),
    col: z.union([
      z.number().int(),
      z.enum(['end'])
    ]).optional().describe(
      '0-indexed UTF-16 offset applied to the line. Negative index counts back ' +
      'from the end of the line (including line breaks). Can also input ' +
      "'end' to represent the end of the line. Defaults to 0."
    ),
    text: z.string().optional().describe('New text to insert at the given position. Optional.'),
    deleteText: z.union([
      z.number().int(),
      z.string(),
      z.boolean()
    ]).optional().describe(
      'Specifies deletion behavior: a number sets the character length (negative counts from the end), ' +
      'a string targets its first occurrence, true represents the maximum length, and false is ignored.'
    )
  })).min(1, "At least one edit must be provided").describe('Edits to apply to the file. Only one edit per line is allowed.'),
  dryRun: z.boolean().optional().describe('If true, do not actually write the file.')
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
  path: z.string().describe('Path of the file to edit; must resolve inside an allowed directory. Prefer absolute paths.'),
  edits: z.array(z.object({
    oldText: z.string().describe(
      'Exact text to find (may span lines). Only its first occurrence is replaced, so add ' +
      'context to make it unique; falls back to whitespace-insensitive line matching that ' +
      'preserves indentation.'
    ),
    newText: z.string().describe('Replacement text; may be empty to delete the match.')
  })).describe('Applied in order; if any oldText is not found the call fails and the file is unchanged.'),
  dryRun: z.boolean().default(false).describe('Preview the git-style diff without writing.')
});

const SearchTextInFileArgsSchema = z.object({
  path: z.string().describe(
    'Path of the file to search; must resolve inside an allowed directory. Prefer absolute paths.'
  ),
  pattern: z.string().describe(
    'JavaScript RegExp (flags g and m, plus i unless caseSensitive). Escape metacharacters ' +
    'for a literal search; an invalid pattern fails the call.'
  ),
  maxResults: z.number().int()
    .min(1, 'maxResults must be >= 1')
    .max(100, 'maxResults must be <= 100').optional()
    .describe(
      'Maximum matches to return (1-100, default 100). The cap is not flagged, so page with ' +
      'skip when more may exist.'
    ),
  skip: z.number().int().min(0).optional().describe(
    'Matches to discard from the start of the file, applied before maxResults.'
  ),
  caseSensitive: z.boolean().optional().describe(
    'Case-sensitive matching. Defaults to false.'
  )
})

const RemoveFilesArgsSchema = z.object({
  paths: z
    .array(z.string())
    .min(1, "At least one file path must be provided")
    .describe("Array of file paths to remove. Each path must be a string pointing to a valid file within allowed directories."),
  recursive: z.boolean().optional().describe("If true, remove files and directories recursively.")
})

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

function checkSnakeCaseKeys<T>(toolName: string, obj: T, schema: unknown) {
  if (!schema || typeof obj !== 'object')
    return;
  if (Array.isArray(obj)) {
    if (!(schema instanceof z.ZodArray))
      return;
    obj.forEach(item => checkSnakeCaseKeys(toolName, item, schema.element));
  }
  if (!(schema instanceof z.ZodObject))
    return;
  const shape = schema.shape;
  const keys = new Set(Object.keys(obj as object));
  for (const key of keys) {
    const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
    if (!shape[key] && shape[camelKey] && !keys.has(camelKey))
      throw new McpError(
        ErrorCode.InvalidParams,
        `Input validation error: Invalid arguments for tool ${toolName}: Unrecognized key: "${key}". Do you mean "${camelKey}"?`
      );
  }
}

const registerTool = <
  OutputArgs extends ZodRawShapeCompat | AnySchema,
  InputArgs extends undefined | ZodRawShapeCompat | AnySchema = undefined
>(
  name: string,
  config: {
    title?: string;
    description?: string;
    inputSchema: InputArgs;
    outputSchema?: OutputArgs;
    annotations?: ToolAnnotations;
    _meta?: Record<string, unknown>;
  },
  cb: ToolCallback<InputArgs>
): RegisteredTool => {
  const { title, description, inputSchema, outputSchema, annotations, _meta } = config;
  if (inputSchema instanceof z.ZodObject) {
    const origRun = inputSchema._zod.run.bind(inputSchema._zod);
    inputSchema._zod.run = (payload, ctx) => {
      checkSnakeCaseKeys(name, payload.value, inputSchema);
      return origRun(payload, ctx);
    };
  }

  return server.registerTool(
    name,
    {
      title,
      description,
      inputSchema,
      outputSchema,
      annotations,
      _meta
    },
    cb
  );
};

// Tool registrations

registerTool(
  "read_text_file",
  {
    title: "Read Text File",
    description: [
      "Read one text file inside the allowed directories. Use read_multiple_files for several " +
      "files at once, and read_media_file for images or audio.",
      "",
      "Result: a key-value header (fileSize, totalLines, plus lineEnding/truncatedAt/next/note when " +
      "relevant), then content: each line as an ABSOLUTE 1-indexed number followed by '|' and " +
      "the line's text (empty lines included).",
      "- lineEnding: line terminator type in the extracted text, LF, CRLF, or Mixed.",
      "- truncatedAt { line, col, lineLength } + next { startLine, startCol }: set when maxSize " +
      "cut the payload short; pass next back verbatim to resume, until next is absent.",
      "- note: why the result needs explaining, e.g. startLine past EOF or a binary file.",
      "",
      "maxSize (0-25000, default 25000) counts UTF-16 units of line content without terminators and " +
      "only caps the payload; the file is still scanned to EOF, so totalLines is exact. Prefer " +
      "ranges over huge files."
    ].join('\n'),
    inputSchema: ReadTextFileArgsSchema,
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ReadTextFileArgsSchema>) => {
    const validPath = await validatePath(args.path);

    const result = await readFile(validPath, args);
    let text = `fileSize: ${result.fileSize}\ntotalLines: ${result.totalLines}\n`;
    const JsonStringifyWithoutKeyQuotes = (obj: unknown) => JSON.stringify(obj).replace(/"([^"]+)"\s*:/g, ' $1: ').replace(/}/, ' }');
    if (result.lineEnding)
      text += `lineEnding: ${result.lineEnding}\n`;
    if (result.truncatedAt)
      text += `truncatedAt: ${JsonStringifyWithoutKeyQuotes(result.truncatedAt)}\nnext: ${JsonStringifyWithoutKeyQuotes(result.next)}\n`;
    if (result.note)
      text += `note: ${result.note}\n`;
    text += `content:\n${result.lines.map((line, i) => `${i + (args.startLine ?? 1)}|${line}`).join('\n')}`;

    return {
      content: [{ type: "text" as const, text }]
    };
  }
);

registerTool(
  "edit_text_file",
  {
    title: "Edit Text File",
    description:
      "Line/column-addressed edits: each edit targets one 1-indexed line (duplicates " +
      "rejected) to insert text, delete characters, or delete the whole line; lines past " +
      "EOF are skipped, original line endings preserved. Use when you know exact positions " +
      "(e.g. from read_text_file); if you only know the text to change, use edit_file " +
      "instead (search-and-replace returning a git-style diff). " +
      "Result: modified lines as <sign><line_number>|<text>, where '-' rows give the " +
      "BEFORE-edit line number (old text) and '+' rows the AFTER-edit line number (new " +
      "text); a note is appended when relevant.",
    inputSchema: EditTextFileArgsSchema,
    annotations: { destructiveHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof EditTextFileArgsSchema>) => {
    const validPath = await validatePath(args.path);

    const result = await editFile(validPath, args.edits, args.dryRun);
    let text = `modified:${result.modified.sort((a, b) => a.line - b.line).map(item => `\n${item.type}${item.line}|${item.text}`).join('')}`;
    if (result.note)
      text += `\nnote: ${result.note}`;

    return {
      content: [{ type: "text" as const, text }]
    };
  }
);

registerTool(
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

registerTool(
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

registerTool(
  "write_file",
  {
    title: "Write File",
    description:
      "Create a new file or completely overwrite an existing file with new content. " +
      "Use with caution as it will overwrite existing files without warning. " +
      "Handles text content with proper encoding.",
    inputSchema: WriteFileArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { idempotentHint: true, destructiveHint: true, openWorldHint: false }
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

registerTool(
  "edit_file",
  {
    title: "Edit File",
    description:
      "Search-and-replace edits addressed by CONTENT, not line numbers: find oldText and " +
      "replace it with newText. Use when you know WHAT to change but not WHERE; use " +
      "edit_text_file when you have exact line/column positions (it returns modified lines " +
      "instead of a diff). Edits apply in order; only the first occurrence of oldText is " +
      "replaced, so include context to make it unique (whitespace-insensitive line matching " +
      "is the fallback). If oldText is not found the call fails and the file is unchanged. " +
      "Returns a git-style diff; dryRun previews without writing. Write is atomic and " +
      "normalizes line endings to LF.",
    inputSchema: EditFileArgsSchema,
    outputSchema: { content: z.string() },
    annotations: { destructiveHint: true, openWorldHint: false }
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

registerTool(
  "search_text_in_file",
  {
    title: "Search Text in File",
    description: [
      "Search one file for a pattern and report each match's position. pattern is a JavaScript " +
      "RegExp (flags g, m, plus i unless caseSensitive); escape metacharacters for a literal " +
      "search.",
      "",
      "Result: 'matches: <n>' (returned count, not total), then one line per match " +
      "<line>:<col>|<json_escaped_text> - line 1-indexed, col 0-indexed UTF-16 within the line, " +
      "text JSON-escaped without outer quotes. 'note: ...' is appended when relevant (NUL byte " +
      "= binary). Empty result is 'matches: 0'. maxResults (default 100, applied after skip) " +
      "is not flagged when hit, so page with skip. Use search_files to find files, " +
      "read_text_file to read around a match."
    ].join('\n'),
    inputSchema: SearchTextInFileArgsSchema,
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof SearchTextInFileArgsSchema>) => {
    const validPath = await validatePath(args.path);

    const result = await searchText(validPath, args.pattern, args);
    let text = `matches: ${result.results.length}` +
      result.results.map(r => `\n${r.line}:${r.col}|${JSON.stringify(r.text).slice(1, -1)}`).join('');
    if (result.note)
      text += `\nnote: ${result.note}`;
    return {
      content: [{ type: "text" as const, text }]
    };
  }
);

registerTool(
  "remove_files",
  {
    title: "Remove Files",
    description:
      "Permanently delete each path - no trash, no undo. Paths are processed independently " +
      "and reported as 'succeed: N' / 'failed: N' with per-path error messages, so partial " +
      "success is possible. Directories are only removed when recursive: true (covers " +
      "non-empty trees); otherwise directory paths fail. Use move_file to relocate instead " +
      "of deleting.",
    inputSchema: RemoveFilesArgsSchema,
    annotations: { destructiveHint: true, idempotentHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof RemoveFilesArgsSchema>) => {
    const succeed: string[] = [];
    const failed: { path: string; error: Error }[] = [];
    for (const path of args.paths)
      try {
        const validPath = await validatePath(path);
        await fs.rm(validPath, { recursive: args.recursive ?? false });
        succeed.push(path);
      } catch (e) {
        failed.push({ path, error: e as Error });
      }

    let text = '';
    if (succeed.length)
      text += `succeed: ${succeed.length}\n${succeed.join("\n")}`
    if (failed.length) {
      if (text)
        text += "\n\n"
      text += `failed: ${failed.length}\n${failed.map(({ path, error }) => `${path}: ${error.message}`).join("\n")}`
    }
    return {
      content: [{ type: "text" as const, text }]
    };
  }
);

registerTool(
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
    annotations: { idempotentHint: true, openWorldHint: false }
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

registerTool(
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

registerTool(
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

registerTool(
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

registerTool(
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
    annotations: { destructiveHint: true, openWorldHint: false }
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

registerTool(
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
    const results = await searchFilesWithValidation(validPath, args.pattern, { excludePatterns: args.excludePatterns });
    const text = results.length > 0 ? results.join("\n") : "No matches found";
    return {
      content: [{ type: "text" as const, text }],
      structuredContent: { content: text }
    };
  }
);

registerTool(
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

registerTool(
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
    let text = `Allowed directories:${allowedDirectories.map(dir => `\n${dir}`).join('')}`;
    if (forbiddenDirectories.length)
      text += `\n\nForbidden directories:${forbiddenDirectories.map(dir => `\n${dir}`).join('')}`;
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
