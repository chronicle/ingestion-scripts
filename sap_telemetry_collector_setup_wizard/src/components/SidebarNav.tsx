import React from 'react';
import {WizardStepId} from '../types';
import {WIZARD_STEPS} from '../data/defaults';
import {CheckCircle} from 'lucide-react';

interface SidebarNavProps {
  currentStep: WizardStepId;
  onStepChange: (step: WizardStepId) => void;
  completedSteps: WizardStepId[];
}

/**
 * SidebarNav component rendering step navigation indicators with status badges
 * showing active, completed, and pending steps in the wizard.
 */
export const SidebarNav: React.FC<SidebarNavProps> = ({
  currentStep,
  onStepChange,
  completedSteps
}) => {
  return (
    <aside className="w-72 bg-slate-50 border-r border-slate-200 flex flex-col shrink-0">
      <nav className="flex-1 p-5 space-y-2 overflow-y-auto">
        <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider px-3 mb-2">
          Guided Steps
        </div>

        {WIZARD_STEPS.map((step) => {
          const isActive = currentStep === step.id;
          const isCompleted = completedSteps.includes(step.id);

          return (
            <button
              key={step.id}
              onClick={() => onStepChange(step.id)}
              className={`w-full flex items-center gap-3 p-3 rounded-lg text-left transition ${
                isActive
                  ? 'bg-white border border-slate-200 shadow-sm ring-1 ring-[#1A73E8]/30'
                  : isCompleted
                  ? 'bg-slate-100/80 text-slate-700 hover:bg-white'
                  : 'text-slate-500 hover:bg-slate-100'
              }`}
            >
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition shrink-0 ${
                  isActive
                    ? 'bg-[#1A73E8] text-white shadow-xs'
                    : isCompleted
                    ? 'bg-[#34A853] text-white'
                    : 'border border-slate-300 bg-white text-slate-600'
                }`}
              >
                {isCompleted ? <CheckCircle className="w-4 h-4" /> : step.id}
              </div>

              <div className="flex-1 min-w-0">
                <div
                  className={`text-xs font-semibold truncate ${
                    isActive ? 'text-slate-900 font-bold' : 'text-slate-700'
                  }`}
                >
                  {step.shortTitle}
                </div>
                <div className="text-[11px] text-slate-400 truncate mt-0.5">
                  {step.badgeText}
                </div>
              </div>

              {isActive && (
                <div className="w-1.5 h-6 bg-[#1A73E8] rounded-full shrink-0"></div>
              )}
            </button>
          );
        })}
      </nav>
    </aside>
  );
};
