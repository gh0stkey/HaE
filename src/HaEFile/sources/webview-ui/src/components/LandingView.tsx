import React from 'react';
import './LandingView.css';

interface LandingViewProps {
  isScanActive: boolean;
  onScanWorkspace: () => void;
}

const LandingView: React.FC<LandingViewProps> = ({ isScanActive, onScanWorkspace }) => {
  return (
    <div className={`landing-state ${isScanActive ? 'landing-state--active' : ''}`}>
      <div className="landing-ambient">
        <span className="ambient-dot" style={{ top: '15%', left: '12%', animationDelay: '0s' }} />
        <span
          className="ambient-dot"
          style={{ top: '25%', right: '18%', animationDelay: '1.5s' }}
        />
        <span
          className="ambient-dot"
          style={{ bottom: '20%', left: '22%', animationDelay: '3s' }}
        />
        <span className="ambient-dot" style={{ top: '40%', left: '6%', animationDelay: '2s' }} />
        <span
          className="ambient-dot"
          style={{ bottom: '30%', right: '10%', animationDelay: '0.8s' }}
        />
        <span
          className="ambient-dot"
          style={{ top: '10%', right: '35%', animationDelay: '2.5s' }}
        />
        <span
          className="ambient-dot"
          style={{ bottom: '12%', left: '40%', animationDelay: '1s' }}
        />
        <span
          className="ambient-line"
          style={{ top: '20%', left: '8%', width: '30px', animationDelay: '0.5s' }}
        />
        <span
          className="ambient-line"
          style={{ bottom: '25%', right: '12%', width: '24px', animationDelay: '2.2s' }}
        />
        <span
          className="ambient-line"
          style={{ top: '55%', right: '20%', width: '20px', animationDelay: '3.5s' }}
        />
      </div>
      <div
        className="hae-orb"
        role="button"
        tabIndex={isScanActive ? -1 : 0}
        onClick={!isScanActive ? onScanWorkspace : undefined}
        onKeyDown={
          !isScanActive
            ? (e) => {
                if (e.key === 'Enter' || e.key === ' ') onScanWorkspace();
              }
            : undefined
        }
      >
        <div className="orb-eye-shell"></div>
        <div className="orb-iris"></div>
        <div className="orb-scanline"></div>

        <div className="orb-center"></div>

        <div className="orb-ring orb-ring-1"></div>
        <div className="orb-ring orb-ring-2"></div>
        <div className="orb-ring orb-ring-3"></div>
        <div className="orb-sweep"></div>
      </div>

      <div className="landing-text">
        <div className="landing-idle-text">
          <div className="landing-title">HaEEye</div>
          <div className="landing-subtitle">Scan the workspace with the eye</div>
        </div>
        <div className="landing-scan-text">
          <div className="landing-title">HaERadar</div>
          <div className="landing-subtitle">Scanning...</div>
        </div>
      </div>
    </div>
  );
};

export default LandingView;
