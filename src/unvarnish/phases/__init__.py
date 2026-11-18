from __future__ import annotations

from unvarnish.phases.base import Phase


def default_phases() -> list[Phase]:
    from unvarnish.phases.extract import ExtractPhase
    from unvarnish.phases.git import GitPhase
    from unvarnish.phases.inventory import InventoryPhase
    from unvarnish.phases.render import RenderPhase
    from unvarnish.phases.rollup_modules import RollupModulesPhase
    from unvarnish.phases.rollup_tool import RollupToolPhase
    from unvarnish.phases.scan import ScanPhase
    from unvarnish.phases.split import SplitPhase
    from unvarnish.phases.verify import VerifyPhase

    return [InventoryPhase(), GitPhase(), ScanPhase(), SplitPhase(), ExtractPhase(),
            RollupModulesPhase(), RollupToolPhase(), VerifyPhase(), RenderPhase()]
