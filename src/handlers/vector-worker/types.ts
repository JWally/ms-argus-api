export interface VectorSearchMessage {
  type: "search";
  session_id: string;
  device_id: string;
  vector: number[];
  collection: string;
  limit?: number;
}

export interface VectorUpsertMessage {
  type: "upsert";
  device_id: string;
  vector: number[];
  collection: string;
  payload?: Record<string, unknown>;
}

export interface WarmupMessage {
  warmup: true;
  source?: string;
}

export type VectorMessage =
  | VectorSearchMessage
  | VectorUpsertMessage
  | WarmupMessage;
