import { tmpdir } from "node:os";
import { join } from "node:path";

if (!process.env.STAMP_PEER_WATCH_LOG) {
  process.env.STAMP_PEER_WATCH_LOG = join(tmpdir(), `stamp-test-peer-watch-${process.pid}.log`);
}
