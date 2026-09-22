import {useState, useEffect} from 'react';
import {AppState, WizardStepId} from './types';
import {INITIAL_APP_STATE} from './data/defaults';
import {Header} from './components/Header';
import {SidebarNav} from './components/SidebarNav';
import {Step1CollectorConfig} from './components/Step1CollectorConfig';
import {Step2GcsConfig} from './components/Step2GcsConfig';
import {Step3GceConfig} from './components/Step3GceConfig';
import {Step4BindplaneConfig} from './components/Step4BindplaneConfig';
import {Step5DockerConfig} from './components/Step5DockerConfig';
import {Step6TerraformExecution} from './components/Step6TerraformExecution';
import {Check, ArrowRight, ArrowLeft, Save, RotateCcw, Download, Play} from 'lucide-react';

/**
 * Root application component managing wizard steps, global state,
 * and step navigation for the SAP Telemetry Collector setup guide.
 */
export function App() {
  const [state, setState] = useState<AppState>(() => {
    const savedDraft = localStorage.getItem('sap_telemetry_wizard_draft');
    if (savedDraft) {
      try {
        const parsed = JSON.parse(savedDraft);
        if (parsed.collector && parsed.gcs) {
          return parsed;
        }
      } catch (err) {
        console.error("Failed to load draft state", err);
      }
    }
    return INITIAL_APP_STATE;
  });

  const [currentStep, setCurrentStep] = useState<WizardStepId>(() => {
    const savedStep = localStorage.getItem('sap_telemetry_wizard_step');
    return savedStep ? (Number(savedStep) as WizardStepId) : 1;
  });

  const [completedSteps, setCompletedSteps] = useState<WizardStepId[]>(() => {
    const savedCompleted = localStorage.getItem('sap_telemetry_wizard_completed');
    if (savedCompleted) {
      try {
        return JSON.parse(savedCompleted);
      } catch (e) {}
    }
    return [];
  });

  const [saveNotification, setSaveNotification] = useState<string | null>(null);

  useEffect(() => {
    const savedDraft = localStorage.getItem('sap_telemetry_wizard_draft');
    if (savedDraft) {
      setSaveNotification("Restored draft configuration from your previous session!");
      setTimeout(() => setSaveNotification(null), 3500);
    }
  }, []);

  const handleReset = () => {
    if (confirm("Reset configuration back to default values?")) {
      localStorage.removeItem('sap_telemetry_wizard_draft');
      localStorage.removeItem('sap_telemetry_wizard_step');
      localStorage.removeItem('sap_telemetry_wizard_completed');
      setState(INITIAL_APP_STATE);
      setCurrentStep(1);
      setCompletedSteps([]);
      setSaveNotification("Configuration reset to clean initial state.");
      setTimeout(() => setSaveNotification(null), 3000);
    }
  };

  const handleNext = () => {
    if (!completedSteps.includes(currentStep)) {
      setCompletedSteps([...completedSteps, currentStep]);
    }
    if (currentStep < 6) {
      setCurrentStep((currentStep + 1) as WizardStepId);
    }
  };

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep((currentStep - 1) as WizardStepId);
    }
  };

  const handleSaveDraft = () => {
    localStorage.setItem('sap_telemetry_wizard_draft', JSON.stringify(state));
    localStorage.setItem('sap_telemetry_wizard_step', currentStep.toString());
    localStorage.setItem('sap_telemetry_wizard_completed', JSON.stringify(completedSteps));
    setSaveNotification("Draft saved to browser storage! Progress will auto-load when you revisit.");
    setTimeout(() => setSaveNotification(null), 3500);
  };

  const [step6Actions, setStep6Actions] = useState<{
    downloadZip: () => void;
    downloadPurge: () => void;
    runInstallation: () => void;
    isExecuting: boolean;
  } | null>(null);

  const getNextButtonLabel = () => {
    switch (currentStep) {
      case 1: return "Continue to GCS Setup";
      case 2: return "Continue to Compute Instance";
      case 3: return "Continue to Bindplane Agent";
      case 4: return "Continue to Docker Setup";
      case 5: return "Proceed to Terraform & Deploy";
      case 6: return "Review Architecture & Execution";
      default: return "Continue";
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen font-sans text-slate-800 bg-[#F8F9FA] overflow-hidden">
      {/* Save Notification Banner */}
      {saveNotification && (
        <div className="fixed top-20 right-6 z-50 bg-slate-900 text-white px-4 py-2.5 rounded-lg shadow-xl text-xs font-semibold flex items-center gap-2 border border-slate-700 animate-in fade-in">
          <Check className="w-4 h-4 text-emerald-400" />
          <span>{saveNotification}</span>
        </div>
      )}

      {/* Top Header */}
      <Header />

      {/* Main Workspace Body */}
      <main className="flex flex-1 overflow-hidden">
        {/* Left Sidebar Steps */}
        <SidebarNav
          currentStep={currentStep}
          onStepChange={setCurrentStep}
          completedSteps={completedSteps}
        />

        {/* Step Dynamic Content View */}
        <section className="flex-1 flex overflow-hidden">
          {currentStep === 1 && (
            <Step1CollectorConfig
              collector={state.collector}
              onChange={(updated) => setState({ ...state, collector: updated })}
              projectId={state.gcs.projectId}
            />
          )}

          {currentStep === 2 && (
            <Step2GcsConfig
              gcs={state.gcs}
              onChange={(updated) => setState({ ...state, gcs: updated })}
              fullState={state}
            />
          )}

          {currentStep === 3 && (
            <Step3GceConfig
              gce={state.gce}
              onChange={(updated) => setState({ ...state, gce: updated })}
              fullState={state}
            />
          )}

          {currentStep === 4 && (
            <Step4BindplaneConfig
              bindplane={state.bindplane}
              onChange={(updated) => setState({ ...state, bindplane: updated })}
              fullState={state}
            />
          )}

          {currentStep === 5 && (
            <Step5DockerConfig
              docker={state.docker}
              onChange={(updated) => setState({ ...state, docker: updated })}
              fullState={state}
            />
          )}

          {currentStep === 6 && (
            <Step6TerraformExecution
              state={state}
              onChange={(updated) => setState(updated)}
              onRegisterActions={setStep6Actions}
            />
          )}
        </section>
      </main>

      {/* Wizard Action Footer matching design HTML */}
      <footer className="h-20 bg-white border-t border-slate-200 flex items-center justify-between px-10 shrink-0 z-20">
        <button
          onClick={handleBack}
          disabled={currentStep === 1}
          className={`flex items-center gap-2 px-6 py-2.5 text-xs font-bold rounded-md transition ${
            currentStep === 1
              ? 'text-slate-300 cursor-not-allowed bg-slate-50'
              : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900 border border-slate-200'
          }`}
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back</span>
        </button>

        <div className="flex items-center gap-3">
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-4 py-2.5 text-xs font-bold text-slate-600 hover:text-red-600 hover:bg-red-50 border border-slate-200 rounded-md transition shadow-2xs"
            title="Clear saved draft cache and reset all fields to clean defaults"
          >
            <RotateCcw className="w-3.5 h-3.5 text-slate-500" />
            <span>Clear Cache</span>
          </button>

          <button
            onClick={handleSaveDraft}
            className="flex items-center gap-2 px-5 py-2.5 text-xs font-bold text-slate-700 hover:bg-slate-100 border border-slate-200 rounded-md transition shadow-2xs"
          >
            <Save className="w-3.5 h-3.5 text-slate-500" />
            <span>Save Draft</span>
          </button>

          {currentStep === 6 && step6Actions && (
            <>
              <button
                type="button"
                onClick={step6Actions.downloadZip}
                className="flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-md shadow-2xs transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Terraform (.ZIP)</span>
              </button>

              <button
                type="button"
                onClick={step6Actions.runInstallation}
                disabled={step6Actions.isExecuting}
                className="flex items-center gap-2 px-5 py-2.5 bg-[#1A73E8] hover:bg-blue-700 text-white font-bold text-xs rounded-md shadow-2xs transition disabled:opacity-50"
              >
                {step6Actions.isExecuting ? (
                  <>
                    <span className="w-3 h-3 rounded-full border-2 border-white border-t-transparent animate-spin"></span>
                    <span>Installing Collector & Provisioning VM...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-white" />
                    <span>Setup and Install SAP Telemetry Collector</span>
                  </>
                )}
              </button>
            </>
          )}

          {currentStep < 6 && (
            <button
              onClick={handleNext}
              className="flex items-center gap-2 px-7 py-2.5 bg-[#1A73E8] hover:bg-blue-700 text-white text-xs font-bold rounded-md shadow-xs transition"
            >
              <span>{getNextButtonLabel()}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </footer>
    </div>
  );
}
