import { hostname } from 'node:os'

/**
 * Derive a human-recognizable device label from the machine hostname.
 * Strips ".local" suffix common on macOS, lowercases.
 */
export function machineLabel(): string {
  return hostname()
    .replace(/\.local$/i, '')
    .toLowerCase()
}

/**
 * Derive a device label for a YubiKey.
 * Uses device name + last 4 of serial to be recognizable but not leaky.
 */
export function yubikeyLabel(deviceName: string, serial: string): string {
  const name = deviceName
    .replace(/Yubico\s+/i, '')
    .replace(/\s+/g, '-')
    .toLowerCase()
  const suffix = serial.slice(-4)
  return `${name}-${suffix}`
}
