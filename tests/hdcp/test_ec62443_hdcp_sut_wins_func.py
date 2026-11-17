# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
TEST — IEC 62443-4-2  HDCP (High-bandwidth Digital Content Protection)  Windows OS  (functional, SUT-only)

Test ID:  IEC62443-4-2-TC_HDCP-FUNC-SUT
Suite:    hdcp

PURPOSE
-------
Verifies that HDCP (High-bandwidth Digital Content Protection) is supported
and active on the platform by guiding the operator through a manual check
in Intel Graphics Command Centre and an optional DRM video playback test.

All verification is manual — HDCP capability is confirmed by reading the
Intel Graphics Command Centre display info page and optionally verifying
that DRM-protected video plays correctly while clear (non-protected) video
also plays.

Why test both videos (Step 4.0)?
  - ENCRYPTED video playing correctly proves the full protected path works
    end-to-end (DRM license -> PAVP-protected decode -> HDCP-encrypted link
    -> display) — the real functional proof of content protection, not just
    a status flag.
  - CLEAR video playing correctly is a control check — it proves playback
    itself isn't broken for unrelated reasons (codec/network/monitor), so an
    ENCRYPTED-video failure can be attributed specifically to the HDCP/DRM
    protected path rather than an unrelated environment issue.

RUN DIRECTLY ON THE WINDOWS SUT (no SSH, no reboot) —
this test runs pytest locally on the Windows SUT.  Both manual checks are
pure OS-level checks (Intel Graphics Command Centre + local video playback),
so no BIOS entry or reboot is required.

Windows has no command-line way to read the HDCP state, so this step is
confirmed by the operator (verification.strict: true in config/test_config.yaml
fails such steps instead).
If HDCP shows 'Not Compatible', write FAIL into the signal file -- the test
fails at once with that note instead of waiting for the timeout.

STEPS
-----
  Step 3.0  — Check HDCP compatibility in Intel Graphics Command Centre
              (+ optional Step 4.0 DRM video playback check, same gate)

PRE-TEST (manual, performed before running this script)
-------------------------------------------------------
  1.0)  Flash IFWI and deploy Windows custom image to boot device.
        - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.
        - Any version from the current BOM release is acceptable.
        - Example (PTL board):
          ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin
  2.0)  Power ON and boot the SUT to Windows OS.
        Ensure SUT is connected to an HDCP-supported monitor.

CONFIG (hdcp_config.yaml)
--------------------------
  usb_mount                : (optional) keep the state/signal files on this drive, e.g. "D:/"
  manual_gate_timeout_secs : 900            # 15 min per gate (0 = no gate timeout)

RUN (on SUT, Administrator PowerShell)
---------------------------------------
  python -m pytest tests/hdcp/test_ec62443_hdcp_sut_wins_func.py -v -s --setup-confirmed --yes
"""

import logging
from pathlib import Path

import pytest

from tests.sut_base_test import SUTBaseTest
from core.prereq import pre_test_check

logger = logging.getLogger(__name__)

# Signal filename — operator creates this file in the state folder to advance the gate
# (covers both Step 3.0 and the optional Step 4.0 check in one gate)
_SIGNAL_STEP3 = "step3_hdcp_done.txt"

# Test video files (Microsoft PlayReady test assets), cached locally in-repo
# under tests/hdcp/assets/ so playback doesn't depend on internet access on the SUT.
_VIDEO_DIR = Path(__file__).resolve().parent / "assets"
_VIDEO_ENCRYPTED = _VIDEO_DIR / "encrypted" / (
    "tearsofsteel_1080p_60s_24fps.6000kbps.1920x1080.h264-8b.2ch.128kbps.aac.avsep.cenc.mp4"
)
_VIDEO_CLEAR = _VIDEO_DIR / "clear" / (
    "tearsofsteel_1080p_60s_24fps.6000kbps.1920x1080.h264-8b.2ch.128kbps.aac.mp4"
)


@pytest.mark.hdcp
@pytest.mark.manual
class TestEC62443HDCPSUTWinsFunc(SUTBaseTest):
    """
    IEC 62443-4-2 HDCP functional test — runs directly on the Windows SUT.

    Guides the operator through Intel Graphics Command Centre HDCP verification
    and an optional DRM video playback check.  Each step is confirmed by
    creating a signal file (see tests.sut_base_test.SUTBaseTest._wait_for_manual_signal).
    """

    SUITE   = "hdcp"
    TEST_ID = "IEC62443-4-2-TC_HDCP-FUNC-SUT"

    PRE_TEST_CHECKLIST = [
        "1.0)  Flash IFWI and deploy Windows custom image to boot device.",
        "      - IFWI: Bootguard 5 (BtG5) EXTERNAL release — RPSF_SEP5 variant.",
        "      - Any version from the current BOM release is acceptable (no",
        "        specific IFWI version is pinned for this test).",
        "      - Example (PTL board):",
        "        ECG_PTL_PR04_B0A1-XXXODCA_RPSF_SEP5_11E50692_2026ww01.1.02_BE351556_CRB.bin",
        "2.0)  Power ON and boot the SUT to Windows OS.",
        "      Ensure SUT is connected to an HDCP-supported monitor.",
    ]

    def test_ec62443_hdcp_sut_wins_func(
        self,
        request,
        config,
        log_dir,
    ):
        """
        IEC62443-4-2-TC_HDCP-FUNC-SUT

        Single manual gate (no OS read-back exists -> confirmed by the operator):
          Step 3.0 : Verify HDCP compatible in Intel Graphics Command Centre
          Step 4.0 : [Optional] Play encrypted + clear DRM test videos
        """
        self._begin()
        cfg = self._load_config(config)
        mgr = self._init_state_dir(cfg)

        pre_test_check(request, self.TEST_ID, self.PRE_TEST_CHECKLIST)

        timeout = int(cfg.get("manual_gate_timeout_secs", 900))

        # ==================================================================
        # Step 3.0 — Verify HDCP via Intel Graphics Command Centre
        #            (+ optional Step 4.0 DRM video playback check)
        # ==================================================================
        self._wait_for_manual_signal(
            signal_file=_SIGNAL_STEP3,
            step_label="3.0",
            timeout_secs=timeout,
            confirms="HDCP = Compatible in Intel Graphics Command Centre (Display -> Information)",
            instructions=[
                "─" * 64,
                "STEP 3.0 — Verify HDCP via Intel Graphics Command Centre",
                "─" * 64,
                "3.1) On the SUT Windows OS, open the",
                "     'Intel Graphics Command Centre' application.",
                "     (Search for it in the Start menu if needed.)",
                "",
                "3.2) Navigate to:",
                "       Display --> Information",
                "",
                "3.3) Locate the HDCP field.",
                "     Expected value: Compatible",
                "     (This requires the connected monitor to support HDCP.)",
                "",
                "     If the value shows 'Not Compatible':",
                "       - Verify the monitor supports HDCP.",
                "       - Try a different HDCP-certified cable or monitor.",
                "       - Still 'Not Compatible'? Write FAIL into the signal file (see below).",
                "",
                "─" * 64,
                "4.0) [OPTIONAL] DRM video playback verification",
                "     This step verifies the end-to-end DRM pipeline using",
                "     Microsoft PlayReady test assets (cached locally in-repo).",
                "",
                "     Why test both videos?",
                "       - ENCRYPTED video playing correctly proves the full",
                "         protected path works end-to-end (DRM license -->",
                "         PAVP-protected decode --> HDCP-encrypted link -->",
                "         display). This is the real functional proof that",
                "         content protection is active, not just a status flag.",
                "       - CLEAR video playing correctly is a control check --",
                "         it proves playback itself isn't broken for unrelated",
                "         reasons (codec/network/monitor). If CLEAR plays but",
                "         ENCRYPTED does not, that isolates the failure to the",
                "         HDCP/DRM protected path specifically.",
                "",
                "4.1) Open File Explorer (or your default media player) on the SUT.",
                "",
                "4.2) Play the ENCRYPTED (DRM-protected) test video:",
                f"     {_VIDEO_ENCRYPTED}",
                "     Expected: Video plays correctly with DRM protection.",
                "",
                "4.3) Play the CLEAR (non-protected) test video:",
                f"     {_VIDEO_CLEAR}",
                "     Expected: Video plays correctly without DRM.",
                "",
                "     This step is optional — skip it if not required.",
                "─" * 64,
            ],
        )
        logger.info("[Step 3.0] Done — HDCP result confirmed by the operator (Display -> Information -> HDCP)")

        mgr.cleanup()
        self._end()
