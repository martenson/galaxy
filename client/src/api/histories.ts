import { fetcher } from "@/api/schema";

export const historiesFetcher = fetcher.path("/api/histories").method("get").create();
export const archivedHistoriesFetcher = fetcher.path("/api/histories/archived").method("get").create();
export const deleteHistory = fetcher.path("/api/histories/{history_id}").method("delete").create();
export const undeleteHistory = fetcher.path("/api/histories/deleted/{history_id}/undelete").method("post").create();
export const historiesQuery = fetcher.path("/api/histories/query").method("get").create();
