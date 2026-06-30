import React from 'react';
import './Brand.css';

interface BrandProps {
  logoUri?: string;
}

const Brand: React.FC<BrandProps> = ({ logoUri }) => {
  return (
    <div className="app-brand">
      <div className="brand-logo">
        {logoUri && <img src={logoUri} alt="HaE" width="24" height="24" />}
      </div>
      <div className="brand-text">
        <span className="brand-name">Highlighter and Extractor</span>
        <span className="brand-slogan">Empower ethical hacker for efficient operations.</span>
      </div>
    </div>
  );
};

export default Brand;
