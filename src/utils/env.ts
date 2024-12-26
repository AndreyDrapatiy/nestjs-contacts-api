import * as dotenv from 'dotenv';

dotenv.config();

/**
 * Retrieves the value of an environment variable.
 * @param name - The name of the environment variable.
 * @param defaultValue - Optional default value to use if the variable is not set.
 * @returns The environment variable value as a string.
 * @throws If the environment variable is not set and no default value is provided.
 */
export default function env(name: string, defaultValue?: string): string {
  const value = process.env[name];

  if (value !== undefined) return value;

  if (defaultValue !== undefined) return defaultValue;

  throw new Error(`Missing environment variable: ${name}`);
}
