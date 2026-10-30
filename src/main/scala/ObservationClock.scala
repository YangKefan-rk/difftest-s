package difftest

import chisel3._
import chisel3.util.experimental.BoringUtils

// The integration passes the common timebase through its instance boundary.
// Only an explicit, pinned producer-delay contract enables source certification.
object ObservationClock {
  private[difftest] final class SourceContract(
    val maxSampleDelayEdges: Int,
    stableHartId: UInt,
  ) {
    private var nextSourceId = 0

    def allocateSourceId(): Int = {
      require(nextSourceId < 256, "source-prefix producer catalog exceeds its 8-bit index")
      val id = nextSourceId
      nextSourceId += 1
      id
    }

    def hartId(): UInt = BoringUtils.bore(stableHartId)
  }

  private case class Source(cycle: UInt, contract: Option[SourceContract])
  private var source: Option[Source] = None

  private def scopedSource[T](cycle: UInt, contract: Option[SourceContract])(body: => T): T = {
    require(cycle.getWidth == 64)
    val previous = source
    source = Some(Source(cycle, contract))
    try body
    finally source = previous
  }

  def withSource[T](cycle: UInt)(body: => T): T = scopedSource(cycle, None)(body)

  def withSource[T](cycle: UInt, maxSampleDelayEdges: Int, hartId: UInt)(body: => T): T = {
    require(maxSampleDelayEdges >= 0 && maxSampleDelayEdges < 256)
    require(hartId.getWidth > 0 && hartId.getWidth <= 8)
    scopedSource(cycle, Some(new SourceContract(maxSampleDelayEdges, hartId)))(body)
  }

  private[difftest] def sourceContract: Option[SourceContract] = source.flatMap(_.contract)

  def apply(): UInt = {
    val connected = source.getOrElse(throw new IllegalArgumentException("memory observation clock is not connected"))
    BoringUtils.bore(connected.cycle)
  }
}
