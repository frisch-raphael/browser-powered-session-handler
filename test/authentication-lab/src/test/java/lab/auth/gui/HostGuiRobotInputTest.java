package lab.auth.gui;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Ownership and activation policy without creating a native window or generating input in unit tests. */
class HostGuiRobotInputTest {
    private static final class Plan implements HostGuiDriver.RobotInput.ClickPlan {
        boolean targetOwned,focusReveals=true,expireAfterFocus,expired,exposureReveals,exposureMovesTarget;int focusClicks,targetClicks,targetReads,captionReads,exposures;Point clickedTarget;
        List<Point> candidates=List.of(new Point(100,15));final List<Point> moves=new ArrayList<>();
        java.util.function.Predicate<Point> captionOwned=point->true;
        Point targetBefore=new Point(20,40),targetAfter=new Point(35,50);
        @Override public void check(){if(expired)throw new HostGuiSelectors.Failure("GUI_DEADLINE");}
        @Override public Point targetPoint(){targetReads++;return new Point(focusClicks==0&&!(exposureMovesTarget&&exposures>0)?targetBefore:targetAfter);}
        @Override public void expose(){exposures++;if(exposureReveals)targetOwned=true;}
        @Override public void move(Point point){moves.add(new Point(point));}
        @Override public boolean targetOwned(Point point){return targetOwned;}
        @Override public List<Point> captionPoints(){captionReads++;return candidates;}
        @Override public boolean captionOwned(Point point){return captionOwned.test(point);}
        @Override public void focusGesture(Point point){focusClicks++;if(focusReveals)targetOwned=true;if(expireAfterFocus)expired=true;}
        @Override public void targetGesture(Point point){targetClicks++;clickedTarget=new Point(point);}
    }

    @Test void unobscuredTargetGetsOneTargetGestureAndNoFocusGesture() {
        var plan=new Plan();plan.targetOwned=true;
        HostGuiDriver.RobotInput.guardedClick(false,plan);
        assertEquals(1,plan.targetClicks);assertEquals(0,plan.focusClicks);assertEquals(0,plan.captionReads);
        assertEquals(1,plan.exposures);
        assertEquals(plan.targetBefore,plan.clickedTarget);
        assertEquals(List.of(plan.targetBefore,plan.targetBefore),plan.moves);
    }

    @Test void occludedTargetUsesOnlyFirstVerifiedCaptionThenRecomputesTheTarget() {
        var plan=new Plan();plan.candidates=List.of(new Point(100,15),new Point(150,15),new Point(200,15));
        plan.captionOwned=point->point.x==150;
        HostGuiDriver.RobotInput.guardedClick(false,plan);
        assertEquals(1,plan.focusClicks);assertEquals(1,plan.targetClicks);assertEquals(3,plan.targetReads);assertEquals(1,plan.exposures);
        assertEquals(plan.targetAfter,plan.clickedTarget);
        assertEquals(List.of(plan.targetBefore,plan.targetBefore,new Point(100,15),new Point(150,15),plan.targetAfter),plan.moves);
    }

    @Test void noOwnedCaptionMeansNoClickAndTheCandidateSearchIsBounded() {
        var plan=new Plan();plan.candidates=java.util.stream.IntStream.range(0,20).mapToObj(i->new Point(i,15)).toList();
        plan.captionOwned=point->point.x>=9;
        assertEquals("GUI_FOCUS_CAPTION_UNAVAILABLE",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());
        assertEquals(0,plan.focusClicks);assertEquals(0,plan.targetClicks);assertEquals(11,plan.moves.size());
    }

    @Test void lostCaptionOwnershipNeverClicksOrContinuesSearching() {
        var calls=new AtomicInteger();var plan=new Plan();plan.captionOwned=point->calls.incrementAndGet()==1;
        assertEquals("GUI_FOCUS_CAPTION_CHANGED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());
        assertEquals(0,plan.focusClicks);assertEquals(0,plan.targetClicks);assertEquals(2,calls.get());
    }

    @Test void activationThatDoesNotExposeTheTargetCannotCauseATargetGestureOrAFocusRetry() {
        var plan=new Plan();plan.focusReveals=false;
        assertEquals("GUI_CONTROL_OCCLUDED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());
        assertEquals(1,plan.focusClicks);assertEquals(0,plan.targetClicks);assertEquals(1,plan.captionReads);
    }

    @Test void occludedPopupNeverActivatesItsOwnerOrDismissesAndRetries() {
        var plan=new Plan();
        assertEquals("GUI_CONTROL_OCCLUDED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(true,plan)).getMessage());
        assertEquals(0,plan.focusClicks);assertEquals(0,plan.targetClicks);assertEquals(0,plan.captionReads);
        assertEquals(0,plan.exposures);
        plan.targetOwned=true;HostGuiDriver.RobotInput.guardedClick(true,plan);
        assertEquals(1,plan.targetClicks);assertEquals(0,plan.focusClicks);assertEquals(0,plan.captionReads);assertEquals(0,plan.exposures);
    }

    @Test void changedTargetFailurePropagatesWithoutAnyInput() {
        var gestures=new AtomicInteger();
        var plan=new HostGuiDriver.RobotInput.ClickPlan(){
            public Point targetPoint(){return new Point(20,40);}public void move(Point point){}
            public boolean targetOwned(Point point){throw new HostGuiSelectors.Failure("GUI_CONTROL_CHANGED");}
            public List<Point> captionPoints(){throw new AssertionError();}public boolean captionOwned(Point point){throw new AssertionError();}
            public void focusGesture(Point point){gestures.incrementAndGet();}public void targetGesture(Point point){gestures.incrementAndGet();}
        };
        assertEquals("GUI_CONTROL_CHANGED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());assertEquals(0,gestures.get());
    }

    @Test void sameOwnedControlMayFinishMovingBeforeItsSingleGestureWithoutExtraActivation() {
        var plan=new MovingPlan(1);
        HostGuiDriver.RobotInput.guardedClick(false,plan);
        assertEquals(1,plan.gestures);assertEquals(1,plan.exposures);assertEquals(0,plan.focusGestures);
        assertEquals(plan.current,plan.clicked);assertEquals(3,plan.moves);
    }

    @Test void continuouslyMovingControlFailsAfterBoundedPointerOnlyObservations() {
        var plan=new MovingPlan(Integer.MAX_VALUE);
        assertEquals("GUI_CONTROL_CHANGED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());
        assertEquals(0,plan.gestures);assertEquals(0,plan.focusGestures);assertEquals(0,plan.exposures);
        assertTrue(plan.moves<=4,"Pointer settling must remain finite even before the deadline");
    }

    @Test void deadlineOrChangedWindowDuringSettlingNeverProducesAGesture() {
        var expired=new MovingPlan(1);expired.expireOnMove=true;
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,expired)).getMessage());
        assertEquals(0,expired.gestures);assertEquals(1,expired.moves);
        var changed=new MovingPlan(1);changed.changeWindowOnMove=true;
        assertEquals("GUI_WINDOW_CHANGED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,changed)).getMessage());
        assertEquals(0,changed.gestures);assertEquals(1,changed.moves);
    }

    @Test void failureAfterTheSingleTargetGestureNeverSettlesOrClicksAgain() {
        var gestures=new AtomicInteger();
        var plan=new HostGuiDriver.RobotInput.ClickPlan(){
            public Point targetPoint(){return new Point(20,40);}public void move(Point point){}
            public boolean targetOwned(Point point){return true;}
            public List<Point> captionPoints(){throw new AssertionError();}public boolean captionOwned(Point point){throw new AssertionError();}
            public void focusGesture(Point point){throw new AssertionError();}
            public void targetGesture(Point point){gestures.incrementAndGet();throw new HostGuiSelectors.Failure("GUI_CONTROL_CHANGED");}
        };
        assertEquals("GUI_CONTROL_CHANGED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());assertEquals(1,gestures.get());
    }

    private static final class MovingPlan implements HostGuiDriver.RobotInput.ClickPlan {
        Point current=new Point(20,40),clicked;int movesLeft,moves,gestures,exposures,focusGestures;
        boolean expireOnMove,changeWindowOnMove;
        MovingPlan(int movesLeft){this.movesLeft=movesLeft;}
        public void check(){if(expireOnMove&&moves>0)throw new HostGuiSelectors.Failure("GUI_DEADLINE");}
        public Point targetPoint(){if(changeWindowOnMove&&moves>0)throw new HostGuiSelectors.Failure("GUI_WINDOW_CHANGED");return new Point(current);}
        public void move(Point point){moves++;if(movesLeft-->0)current.translate(15,10);}
        public boolean targetOwned(Point point){
            if(!point.equals(targetPoint()))throw new HostGuiSelectors.Failure("GUI_CONTROL_CHANGED");return true;
        }
        public void expose(){exposures++;}
        public List<Point> captionPoints(){return List.of();}public boolean captionOwned(Point point){return false;}
        public void focusGesture(Point point){focusGestures++;}public void targetGesture(Point point){gestures++;clicked=new Point(point);}
    }

    @Test void captionCandidatesStayInsideAnInsetDerivedLeftCentralRegionAwayFromControlsAndEdges() {
        var size=new Dimension(880,650);var insets=new Insets(31,8,8,8);
        var points=HostGuiDriver.RobotInput.captionCandidates(size,insets);
        assertFalse(points.isEmpty());assertTrue(points.size()<=9);assertTrue(points.contains(new Point(440,15)),"The verified diagnostic caption point remains eligible");
        for(Point point:points){assertTrue(point.x>=insets.left+2*insets.top);assertTrue(point.x<=size.width/2);
            assertTrue(point.x<=size.width-insets.right-6*insets.top);assertTrue(point.y>=12);assertTrue(point.y<=26);}
        assertTrue(points.stream().anyMatch(point->point.y<15),"A partially exposed upper caption can be tested without clicking an edge");
    }

    @Test void smallUndecoratedOrInconsistentWindowsHaveNoGuessedCaption() {
        assertTrue(HostGuiDriver.RobotInput.captionCandidates(new Dimension(250,180),new Insets(31,8,8,8)).isEmpty());
        assertTrue(HostGuiDriver.RobotInput.captionCandidates(new Dimension(880,650),new Insets(0,0,0,0)).isEmpty());
        assertTrue(HostGuiDriver.RobotInput.captionCandidates(new Dimension(880,650),new Insets(8,8,8,8)).isEmpty());
        assertTrue(HostGuiDriver.RobotInput.captionCandidates(new Dimension(880,50),new Insets(31,8,8,8)).isEmpty());
        assertTrue(HostGuiDriver.RobotInput.captionCandidates(new Dimension(880,650),new Insets(31,-1,8,8)).isEmpty());
    }

    @Test void foreignOrMismatchedPointerPositionsCannotProveOwnership() {
        assertFalse(HostGuiDriver.RobotInput.matchesOwnedPoint(null,new Point(20,30)));
        assertFalse(HostGuiDriver.RobotInput.matchesOwnedPoint(new Point(22,30),new Point(20,30)));
        assertTrue(HostGuiDriver.RobotInput.matchesOwnedPoint(new Point(20,30),new Point(20,30)));
        assertTrue(HostGuiDriver.RobotInput.matchesOwnedPoint(new Point(21,29),new Point(20,30)));
    }
    @Test void expiryBetweenFocusAndTargetPreventsTheLaterGestureAndPointerMove() {
        var plan=new Plan();plan.expireAfterFocus=true;
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedClick(false,plan)).getMessage());
        assertEquals(1,plan.focusClicks);assertEquals(0,plan.targetClicks);assertEquals(2,plan.targetReads);
        assertEquals(List.of(plan.targetBefore,plan.targetBefore,plan.candidates.getFirst()),plan.moves);
    }
    @Test void exposureCanRevealTheTargetWithoutACaptionGestureAndUsesFreshGeometry() {
        var plan=new Plan();plan.exposureReveals=true;plan.exposureMovesTarget=true;
        HostGuiDriver.RobotInput.guardedClick(false,plan);
        assertEquals(1,plan.exposures);assertEquals(0,plan.focusClicks);assertEquals(1,plan.targetClicks);assertEquals(0,plan.captionReads);
        assertEquals(plan.targetAfter,plan.clickedTarget);assertEquals(List.of(plan.targetBefore,plan.targetAfter),plan.moves);
    }
    @Test void wheelOwnershipAndExpiryAreCheckedBeforeTheSingleWheelInput() {
        var wheels=new AtomicInteger();
        assertEquals("GUI_CONTROL_OCCLUDED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedWheel(()->{},()->false,wheels::incrementAndGet)).getMessage());
        assertEquals(0,wheels.get());
        var expired=new java.util.concurrent.atomic.AtomicBoolean();
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiDriver.RobotInput.guardedWheel(()->{if(expired.get())throw new HostGuiSelectors.Failure("GUI_DEADLINE");},
                        ()->{expired.set(true);return true;},wheels::incrementAndGet)).getMessage());
        assertEquals(0,wheels.get());HostGuiDriver.RobotInput.guardedWheel(()->{},()->true,wheels::incrementAndGet);assertEquals(1,wheels.get());
    }
    @Test void expiryDuringAKeyChordStillReleasesAlreadyPressedKeys() {
        var checks=new AtomicInteger();var pressed=new ArrayList<Integer>();var released=new ArrayList<Integer>();
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiDriver.RobotInput.guardedKeys(new int[]{17,65},
                ()->{if(checks.incrementAndGet()>1)throw new HostGuiSelectors.Failure("GUI_DEADLINE");},pressed::add,released::add)).getMessage());
        assertEquals(List.of(17),pressed);assertEquals(List.of(17),released);
    }
}
