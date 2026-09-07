export function parseQuantity(raw) {
  return Function(`"use strict"; return Number(${raw})`)();
}
