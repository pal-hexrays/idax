# idax — Node.js Bindings

Node.js native bindings for the idax IDA SDK wrapper library.

## Prerequisites

- Node.js >= 18.0.0
- IDA Pro installed
- The idax C++ library built (run `build.sh` from the repo root)

## Setup

### Environment

Set `IDADIR` so the IDA shared libraries can be found at runtime:

```bash
export IDADIR="/Applications/IDA Professional 9.3.app/Contents/MacOS"
export DYLD_LIBRARY_PATH="$IDADIR:$DYLD_LIBRARY_PATH"
```

### Using in a project

```bash
mkdir my-ida-tool && cd my-ida-tool
npm init -y
npm install typescript @types/node tsx --save-dev

# Install idax from the local build
npm install /path/to/idax/bindings/node
```

Or add it directly to your `package.json`:

```json
{
  "dependencies": {
    "idax": "file:../idax/bindings/node"
  }
}
```

## Usage

```typescript
import idax from 'idax';

const { database, function: fn, decompiler } = idax;

database.init({ quiet: true });
database.open('/path/to/binary.i64');

console.log('Processor:', database.processorName());
console.log('Bitness:', database.addressBitness());

// All addresses are BigInt
for (const f of fn.all()) {
    console.log(`${f.name} @ 0x${f.start.toString(16)}`);
}

if (decompiler.available()) {
    const first = fn.all()[0];
    const result = decompiler.decompile(first.start);
    console.log(result.pseudocode());
}

database.close();
```

Run with:

```bash
npx tsx index.ts
```

## API

Full TypeScript definitions are provided in `lib/index.d.ts`. The module exports the following namespaces:

| Namespace | Description |
|-----------|-------------|
| `database` | Lifecycle (init, open, save, close) and metadata |
| `address` | Address navigation and predicates |
| `segment` | Segment manipulation |
| `function` | Function querying and analysis |
| `instruction` | Instruction decoding |
| `name` | Symbol name management |
| `xref` | Cross-references |
| `comment` | Comments |
| `data` | Data items |
| `search` | Binary search |
| `analysis` | Analysis queries |
| `type` | Type information |
| `entry` | Entry points |
| `fixup` | Fixup/relocation information |
| `event` | Event handling |
| `storage` | Storage/attributes |
| `diagnostics` | Diagnostics |
| `lumina` | Lumina integration |
| `lines` | Line/listing information |
| `decompiler` | Hex-Rays decompiler |

All IDA addresses are represented as `bigint`. The sentinel `BadAddress` (`0xFFFFFFFFFFFFFFFFn`) is exported at the top level.

### Error handling

Errors thrown by the native addon extend `Error` with structured metadata:

```typescript
interface IdaxError extends Error {
    category: 'Validation' | 'NotFound' | 'Conflict' | 'Unsupported' | 'SdkFailure' | 'Internal';
    code: number;
    context?: string;
}
```

## Examples

See the `examples/` directory for complete scripts:

- `ida2py_port.ts` — headless symbol/xref/decompilation queries
- `binary_forensics.ts` — binary analysis tools
- `class_reconstructor.ts` — class structure reconstruction
- `complexity_metrics.ts` — code complexity metrics
- `change_tracker.ts` — change tracking
- `sink_tracer.ts` — data flow tracing
- `idalib_dump_port.ts` — IDA library dumping
- `idalib_lumina_port.ts` — Lumina integration

## Building from source

```bash
cd bindings/node
npm install
npm run build
```

Requires the `IDASDK` environment variable pointing to the IDA SDK.
