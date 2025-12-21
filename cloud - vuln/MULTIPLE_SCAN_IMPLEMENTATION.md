# Multiple Container Scan Support - Implementation Summary

## Overview
This document outlines the changes made to enable multiple scans of the same container/image. Previously, the system used idempotency logic to prevent duplicate scans. Now, each scan request creates a new scan entry with a unique ID, allowing the same image to be scanned multiple times.

## Changes Made

### 1. Database Schema Changes
**File**: [migrations/001_initial_schema.sql](migrations/001_initial_schema.sql)

- **Removed UNIQUE constraint** from `idempotency_key` column
- **Updated column comment** to reflect new behavior

**Before**:
```sql
idempotency_key VARCHAR(64) UNIQUE,
```

**After**:
```sql
idempotency_key VARCHAR(64),
```

### 2. SQLAlchemy Model Updates  
**File**: [app/models.py](app/models.py)

- **Updated comments** to clarify multiple scan support
- **Confirmed unique=False** setting on idempotency_key column

### 3. Migration Script for Existing Databases
**File**: [migrations/002_remove_idempotency_unique_constraint.sql](migrations/002_remove_idempotency_unique_constraint.sql) *(new)*

- **Removes UNIQUE constraint** from existing databases
- **Safe to run on existing deployments**
- **Includes error handling** for cases where constraint doesn't exist

### 4. Service Logic Overhaul
**File**: [app/services.py](app/services.py)

#### Major Changes:
- **Always creates new scans** instead of returning cached results
- **Removed cache checking** from main scan submission flow  
- **Simplified logic**: Only checks for in-progress scans (not completed ones)
- **Updated audit messages** to reflect multiple scan support

#### Key Method Changes:

**`submit_scan_request()`**:
- Now always creates new scan unless in-progress scan exists and force=False
- Removed cache hit logic
- Each request gets a unique scan ID

**`generate_idempotency_key()`** in [app/repositories.py](app/repositories.py):
- Now uses high-precision timestamp for uniqueness
- Each scan gets a unique idempotency key
- Format: `hash(registry/image:tag:timestamp_ms)`

### 5. Behavioral Changes

| Scenario | Previous Behavior | New Behavior |
|----------|------------------|--------------|
| Same image scanned twice within 60min | Returns cached result | Creates new scan |
| Same container scanned multiple times | Prevented by idempotency | Each scan gets unique ID |
| Dashboard display | Shows only latest scan per image | Shows all scans |
| In-progress scans | Blocks new scans | Only blocks if force=False |

## How to Apply Changes

### For New Deployments
1. Use the updated [migrations/001_initial_schema.sql](migrations/001_initial_schema.sql)
2. Deploy the updated application code
3. Multiple scans will work immediately

### For Existing Deployments
1. **Run migration script**:
   ```bash
   psql -d your_database -f migrations/002_remove_idempotency_unique_constraint.sql
   ```

2. **Deploy updated application code**

3. **Verify the changes**:
   ```sql
   -- Check that UNIQUE constraint is removed
   SELECT conname, contype
   FROM pg_constraint
   WHERE conrelid = 'vulnerability_scans'::regclass 
   AND conname LIKE '%idempotency%';
   ```

### Testing the Changes
1. **Submit multiple scans** for the same image:
   ```bash
   # Each should create a new scan ID
   curl -X POST "http://localhost:8000/api/scans" \
        -H "Content-Type: application/json" \
        -d '{"image_name": "nginx", "image_tag": "latest"}'
   ```

2. **Check dashboard** - should show multiple scan entries for same image

3. **Verify database** - multiple entries with different IDs but same image info

## Database Impact

### Storage Considerations
- **More scan records**: Same images will have multiple scan entries
- **Disk usage**: Will grow faster due to multiple scans per image
- **Query performance**: May need optimization for large scan volumes

### Recommended Optimizations (Future)
1. **Data retention policy**: Archive old scans after N days
2. **Partitioning**: Partition by created_at for better performance  
3. **Indexing**: Additional indexes on (image_name, created_at) for historical queries

## API Changes

### Request Behavior
- **No breaking changes** to existing API endpoints
- **`force_rescan` parameter** now only affects in-progress scan handling
- **Response format** remains the same

### New Capabilities
- Multiple scans of same image return different scan IDs
- Dashboard shows historical scan data for same image
- Better audit trail for repeated security assessments

## Configuration

### Environment Variables (No Changes Required)
```bash
SCAN_CACHE_TTL_MINUTES=60  # Now only affects in-progress scan detection
SCAN_MAX_RETRIES=3         # Unchanged
```

## Troubleshooting

### Common Issues

1. **Migration fails on existing database**:
   - Constraint might already be removed
   - Check PostgreSQL logs for specific error
   - Safe to ignore if constraint doesn't exist

2. **Multiple scans not appearing**:
   - Verify migration was applied successfully
   - Check application logs for scan creation
   - Ensure force_rescan=true if needed

3. **Performance degradation**:
   - Monitor database size growth
   - Consider implementing data retention policies
   - Add indexes if query performance degrades

### Verification Commands

```bash
# Check if UNIQUE constraint is removed
psql -d vulnerability_scanner -c "
SELECT conname, contype 
FROM pg_constraint 
WHERE conrelid = 'vulnerability_scans'::regclass 
AND conname LIKE '%idempotency%';"

# Test multiple scans
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest"}'

# Should return different scan IDs each time
```

## Summary

The implementation successfully removes the idempotency constraints that prevented multiple scans of the same container/image. Each scan request now:

✅ **Creates a unique scan** with its own ID  
✅ **Appears separately** on the dashboard  
✅ **Maintains full audit trail**  
✅ **Preserves existing API compatibility**  
✅ **Only prevents concurrent in-progress scans** (configurable)  

This enables users to track vulnerability changes over time for the same containers and provides better visibility into security posture changes.