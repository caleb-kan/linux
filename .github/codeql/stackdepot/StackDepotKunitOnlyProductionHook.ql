/**
 * @name Stackdepot production helper used only by KUnit
 * @description Flags stackdepot production helpers that appear to exist only for KUnit tests.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id stackdepot/kunit-only-production-hook
 */

import cpp
import StackDepot

predicate calledFromStackdepotKunit(Function f) {
  exists(FunctionCall call |
    call.getTarget() = f and
    call.getFile().getRelativePath() = "lib/tests/stackdepot_kunit.c"
  )
}

predicate calledFromNonKunit(Function f) {
  exists(FunctionCall call |
    call.getTarget() = f and
    call.getFile().getRelativePath() != "lib/tests/stackdepot_kunit.c"
  )
}

from Function f
where
  isStackDepotFunction(f) and
  not f.getName().matches("%kunit%") and
  calledFromStackdepotKunit(f) and
  not calledFromNonKunit(f)
select f, "Production stackdepot helper '$@' appears KUnit-only; avoid production helper surface just for tests.", f, f.getName()
