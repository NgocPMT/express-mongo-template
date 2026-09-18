export const UPLOAD_LIMITS = {
  BYTES_PER_KB: 1_024,
  BYTES_PER_MB: 1_048_576,
  MAX_FILE_SIZE_MB: 5,
  MAX_FILE_SIZE_BYTES: 5_242_880,
  MAX_FILES: 1,
  WEBP_HEADER_MIN_LENGTH: 12,
  WEBP_RIFF_START: 0,
  WEBP_RIFF_END: 4,
  WEBP_TYPE_START: 8,
  WEBP_TYPE_END: 12,
} as const;

// Magic byte signatures for supported image formats
const JPEG_BYTE_0 = 0xff;
const JPEG_BYTE_1 = 0xd8;
const JPEG_BYTE_2 = 0xff;

const PNG_BYTE_0 = 0x89;
const PNG_BYTE_1 = 0x50;
const PNG_BYTE_2 = 0x4e;
const PNG_BYTE_3 = 0x47;
const PNG_BYTE_4 = 0x0d;
const PNG_BYTE_5 = 0x0a;
const PNG_BYTE_6 = 0x1a;
const PNG_BYTE_7 = 0x0a;

export const IMAGE_SIGNATURES = {
  JPEG: [JPEG_BYTE_0, JPEG_BYTE_1, JPEG_BYTE_2] as const,
  PNG: [
    PNG_BYTE_0,
    PNG_BYTE_1,
    PNG_BYTE_2,
    PNG_BYTE_3,
    PNG_BYTE_4,
    PNG_BYTE_5,
    PNG_BYTE_6,
    PNG_BYTE_7,
  ] as const,
} as const;
