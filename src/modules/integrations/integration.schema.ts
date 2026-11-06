import { z } from "zod";
import { INTEGRATION_SYSTEMS } from "./integration.types";
const payload = z.record(z.string(), z.unknown()).superRefine((v,ctx)=>{
 const encoder = new TextEncoder();
 let visited = 0;
 let estimatedBytes = 0;
 const safe = (x:unknown,d=0):boolean => {
  if(d>8 || ++visited>10_000) return false;
  if(x===null || typeof x==="boolean") return true;
  if(typeof x==="string") {
   estimatedBytes += encoder.encode(x).byteLength;
   return estimatedBytes<=16*1024;
  }
  if(typeof x==="number") return Number.isFinite(x);
  if(Array.isArray(x)) return x.every(y=>safe(y,d+1));
  if(typeof x==="object") {
   return Object.entries(x as Record<string,unknown>).every(([k,y])=>{
    estimatedBytes += encoder.encode(k).byteLength;
    return estimatedBytes<=16*1024 &&
     !/(password|token|secret|api_?key|authorization|student_?name|trainer_?name|phone|mobile|email|aadhaar|aadhar|^dob$)/i.test(k) &&
     safe(y,d+1);
   });
  }
  return false;
 };
 let serialized: string | undefined;
 try {
  if(safe(v)) serialized = JSON.stringify(v);
 } catch {
  serialized = undefined;
 }
 if(serialized===undefined) {
  ctx.addIssue({code:"custom",message:"payload must be bounded JSON and must not contain secrets or direct personal identifiers"});
 } else if(encoder.encode(serialized).byteLength>16*1024) {
  ctx.addIssue({code:"custom",message:"payload must not exceed 16 KB"});
 }
});
export const integrationSourceSchema = z.object({
 code:z.string().trim().min(2).max(60).regex(/^[A-Z][A-Z0-9_]*$/),
 name:z.string().trim().min(2).max(120),system:z.enum(INTEGRATION_SYSTEMS),
 transport:z.enum(["REST","SFTP","CSV_UPLOAD","WEBHOOK"]),enabled:z.boolean().default(false),
 credential_ref:z.string().trim().min(2).max(120).regex(/^[A-Z][A-Z0-9_]*$/).nullable().optional(),
 sync_interval_seconds:z.number().int().min(60).max(86400).nullable().optional(),
}).strict().superRefine((source,ctx)=>{
 if((source.transport==="CSV_UPLOAD"||source.transport==="WEBHOOK")&&source.sync_interval_seconds!=null){
  ctx.addIssue({code:"custom",path:["sync_interval_seconds"],message:"CSV upload and webhook sources cannot use scheduled polling"});
 }
});
export const integrationEnabledSchema=z.object({enabled:z.boolean()}).strict();
export const integrationScheduleSchema=z.object({sync_interval_seconds:z.number().int().min(60).max(86400).nullable()}).strict();
export const integrationIdSchema=z.object({id:z.coerce.number().int().positive()});
export const integrationListSchema=z.object({enabled:z.enum(["true","false"]).optional(),system:z.enum(INTEGRATION_SYSTEMS).optional()});
export const integrationRunSchema=z.object({
 status:z.enum(["SUCCEEDED","PARTIAL","FAILED"]),records_read:z.number().int().min(0).max(1000000),
 records_created:z.number().int().min(0).max(1000000),records_updated:z.number().int().min(0).max(1000000),
 records_rejected:z.number().int().min(0).max(1000000),cursor:z.string().max(2000).nullable().optional(),
 error_code:z.string().max(100).nullable().optional(),error_summary:z.string().max(1000).nullable().optional(),
}).strict().superRefine((v,ctx)=>{
 if(v.status==="FAILED"&&!v.error_code)ctx.addIssue({code:"custom",path:["error_code"],message:"error_code is required for failed runs"});
 if(v.records_created+v.records_updated+v.records_rejected>v.records_read)ctx.addIssue({code:"custom",message:"processed record counts cannot exceed records_read"});
});
/** Runtime envelope validation for untrusted adapter output. */
export const integrationAdapterPageSchema = z.object({
 records: z.array(z.unknown()).max(500),
 nextCursor: z.string().max(2000).nullable().optional(),
 hasMore: z.boolean(),
}).strict().superRefine((page,ctx)=>{
 if(page.hasMore && (!page.nextCursor || page.nextCursor.trim().length===0)) {
  ctx.addIssue({code:"custom",path:["nextCursor"],message:"a non-empty continuation cursor is required when hasMore is true"});
 }
});
const integrationIngestRecordsSchema = z.array(z.object({
 source_record_id:z.string().trim().min(1).max(200),
 source_version:z.string().trim().max(100).nullable().optional(),
 occurred_at:z.string().datetime({offset:true}).nullable().optional(),
 payload,
}).strict()).min(1).max(500).superRefine((records,ctx)=>{
 const seen = new Set<string>();
 records.forEach((record,index)=>{
  if(seen.has(record.source_record_id)){
   ctx.addIssue({
    code:"custom",
    path:[index,"source_record_id"],
    message:"source_record_id must be unique within an ingestion batch",
   });
  }
  seen.add(record.source_record_id);
 });
 let batchBytes = 0;
 try {
  batchBytes = new TextEncoder().encode(JSON.stringify(records)).byteLength;
 } catch {
  ctx.addIssue({code:"custom",message:"records must be serializable JSON"});
  return;
 }
 if(batchBytes>1024*1024) {
  ctx.addIssue({code:"custom",message:"an ingestion batch must not exceed 1 MB of serialized JSON"});
 }
});
export const integrationIngestSchema=z.object({records:integrationIngestRecordsSchema}).strict();
export type IntegrationSourceInput=z.infer<typeof integrationSourceSchema>;
export type IntegrationIngestInput=z.infer<typeof integrationIngestSchema>;
