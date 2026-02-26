import { seedVlans, seedEntities, generateInitialFlows, tickFlows } from "./flows";
import { seedAccessPoints, generateInitialRemote, tickRemote } from "./remote";
import { seedOtDevices, generateInitialOt, tickOt } from "./ot";
import { tickEdges } from "./edges";
import { tickPropagation } from "./propagation";
import { tickCorrelator } from "./correlator";
import { seedShims, tickShims } from "./shims";

let timer: ReturnType<typeof setInterval> | null = null;
let tickCount = 0;

export async function initSimulator() {
  await seedVlans();
  await seedEntities();
  await seedAccessPoints();
  await seedOtDevices();
  await seedShims();

  await generateInitialFlows();
  await generateInitialRemote();
  await generateInitialOt();

  timer = setInterval(async () => {
    try {
      const ts = new Date().toISOString();
      await tickFlows(ts);
      await tickRemote(ts);
      await tickOt(ts);
      await tickShims(ts);

      tickCount++;
      if (tickCount % 6 === 0) {
        await tickEdges(ts);
        await tickPropagation();
        await tickCorrelator(ts);
      }
    } catch (e) {
      console.error("Simulator tick error:", e);
    }
  }, 5000);

  console.log("Simulator started \u2014 generating data every 5s");
}

export function stopSimulator() {
  if (timer) clearInterval(timer);
}
