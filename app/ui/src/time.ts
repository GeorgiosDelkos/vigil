/** How long ago `then` was, briefly: "just now", "5 min", "3 h", "4 days". Formatting only,
 * kept here because it follows the popover's ticking clock. */
/** `since` read as a phrase: "just now", or "5 min ago". */
export function ago(then: string, now: Date): string {
  const span = since(then, now);
  return span === "just now" ? span : `${span} ago`;
}

export function since(then: string, now: Date): string {
  const minutes = Math.floor((now.getTime() - new Date(then).getTime()) / 60_000);
  if (minutes < 1) {
    return "just now";
  }
  if (minutes < 60) {
    return `${minutes} min`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} h`;
  }
  const days = Math.floor(hours / 24);
  return days === 1 ? "1 day" : `${days} days`;
}
