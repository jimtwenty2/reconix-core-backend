/* The Reconix mark: the terminal's cyan ◆ (the TUI's "◆ reconix", reconix/theme.py CYAN) on a
   dark rounded tile, drawn as the favicon draws it (app/icon.svg): a 32-unit square with an 8-unit
   corner radius, and a diamond whose four points sit 10 units from the centre. Colours are tokens:
   the tile --surface, the diamond --globe-glow (the TUI's cyan). Decorative (aria-hidden) beside
   a visible name; give it a `label` where it stands alone. When `variant="bot"` is set, renders
   the robot AI profile icon on the brand tile instead of the diamond. */
import type { SVGProps } from "react";

export interface ReconixMarkProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height" | "viewBox" | "children"> {
  /** Width and height in px (the drawing scales with it). */
  size: number;
  /** Its accessible name when nothing beside it says "Reconix"; without one it is hidden. */
  label?: string;
  /** When set, renders this character on the brand tile (e.g. 'R'). */
  char?: string;
  /** Visual variant: default diamond, robot profile ("bot"), or initial character ("char"). */
  variant?: "diamond" | "bot" | "char";
}

const BOT_PATH =
  "M 14.25 4.5 C 14.25 3.5 15 2.75 16 2.75 C 17 2.75 17.75 3.5 17.75 4.5 C 17.75 5.2 17.3 5.8 16.75 6.1 V 9 H 15.25 V 6.1 C 14.7 5.8 14.25 5.2 14.25 4.5 Z M 3.5 15.5 C 3.5 14.9 4 14.5 4.5 14.5 H 6 V 19.5 H 4.5 C 4 19.5 3.5 19.1 3.5 18.5 Z M 26 14.5 H 27.5 C 28.1 14.5 28.5 14.9 28.5 15.5 V 18.5 C 28.5 19.1 28.1 19.5 27.5 19.5 H 26 Z M 9.5 9 H 22.5 C 24.4 9 26 10.6 26 12.5 V 21.5 C 26 23.4 24.4 25 22.5 25 H 9.5 C 7.6 25 6 23.4 6 21.5 V 12.5 C 6 10.6 7.6 9 9.5 9 Z M 9 15 A 2 2 0 1 0 13 15 A 2 2 0 1 0 9 15 Z M 19 15 A 2 2 0 1 0 23 15 A 2 2 0 1 0 19 15 Z M 12.5 20 H 19.5 C 20.1 20 20.5 20.4 20.5 21 C 20.5 21.6 20.1 22 19.5 22 H 12.5 C 11.9 22 11.5 21.6 11.5 21 C 11.5 20.4 11.9 20 12.5 20 Z";
const R_PATH =
  "M 9.75 8.5 H 17 C 20.2 8.5 22.25 10 22.25 12.5 C 22.25 14.8 20.5 16.2 17.5 16.4 L 22.25 23.5 H 18.2 L 13.75 16.5 V 23.5 H 9.75 Z M 13.75 11.2 V 13.8 H 16.8 C 18.2 13.8 18.8 13.2 18.8 12.5 C 18.8 11.8 18.2 11.2 16.8 11.2 Z";
const DIAMOND_PATH = "M16 6 26 16 16 26 6 16Z";

export function ReconixMark({ size, label, char, variant = char ? "char" : "diamond", ...props }: ReconixMarkProps) {
  const a11y = label ? { role: "img", "aria-label": label } : { "aria-hidden": true };
  const d = variant === "bot" ? BOT_PATH : variant === "char" && char?.toUpperCase() === "R" ? R_PATH : DIAMOND_PATH;
  const isCutout = variant === "bot" || variant === "char";
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} data-reconix-mark="" {...a11y} {...props}>
      <rect width="32" height="32" rx="8" className="fill-surface" />
      <path d={d} className="fill-globe-glow" fillRule={isCutout ? "evenodd" : undefined} />
    </svg>
  );
}
