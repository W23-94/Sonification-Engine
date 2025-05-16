<CsoundSynthesizer>
<CsOptions>
-odac -m4
</CsOptions>
<CsInstruments>

sr = 44100
ksmps = 32
nchnls = 2
0dbfs = 1.0
seed 0

gkTempo init (113 / 60) * 4

giSin ftgen 1, 0, 1024, 10, 1
giSaw ftgen 3, 0, 1024, 10, 1, 0.5, 0.3, 0.25, 0.2, 0.167, 0.14, 0.125, 0.111 ; Sawtooth approximation
giSample ftgen 2, 0, 0, 1, "samples/kick1.aif", 0, 4, 1

; Kick pattern (1 = hit, 0 = silence) - keeping the pattern definition but not using it
giKickPattern ftgen 10, 0, 32, -2, 
  1, 0, 0, 1,  0, 1, 0, 0,  1, 0, 0, 1,  0, 0, 1, 0

; Pluck pattern (1 = hit, 0 = silence)
giPluckPattern ftgen 11, 0, 64, -2, 
  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,
  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,
  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,
  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0


; Ambience pattern (1 = trigger, 0 = silence)
giAmbiencePattern ftgen 12, 0, 4, -2, 
  1, 0, 1, 0, 1, 0, 1, 0,  0, 0, 1, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 1, 0, 0, 0,  0, 0, 0, 0, 0, 0, 1, 0,
  1, 0, 0, 0, 0, 0, 0, 0,  0, 1, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 1, 0, 0, 0, 0,  0, 0, 0, 0, 1, 0, 0, 0

; Pad/Beep pattern (rhythmic pattern)
giPadPattern ftgen 13, 0, 4, -2,
  1, 0, 0, 0, 0, 1, 0, 0,  1, 0, 0, 1, 0, 0, 1, 0,
  0, 1, 0, 0, 1, 0, 0, 1,  0, 0, 1, 0, 1, 0, 0, 0

; Pad chord progression (MIDI note numbers)
giPadChords ftgen 14, 0, 8, -2,
  60, 64, 67, 71,  ; Cmaj7
  62, 65, 69, 72   ; Dm7 (shifted up)

schedule "clock", 0, -1
schedule "fx_reverb", 0, -1

instr clock
  ktrig metro gkTempo
  kstep init 0
  if ktrig == 1 then
    schedulek "sequencer", 0, 0.1, kstep
    kstep += 1
  endif
endin

instr sequencer
  istp = p4
  ipatternPos = istp % 32

  ; Removed kick pattern scheduling

  ; Removed occasional accent kick

  ; Removed random ghost kick

  ; Bassline every step
  if istp % 1 == 0 then
    schedule "_bass", 0, 0.3 + random(0.0, 0.05)
  endif

  ; Removed hi-hats scheduling

  ; Pluck tone sequencing (percussive, non-melodic)
  if table(ipatternPos, giPluckPattern) > 0 then
    iPluckVel = 1 + random(-0.1, 0.1)
    iPluckDur = 2.05 + random(0, 0.05)
    
    ; Increase reverb send amount for this pluck
    iPluckReverb = 1  ; Reverb intensity
    
    schedule "_pluck", 0, iPluckDur, iPluckVel, iPluckReverb
  endif
  
  ; Occasional ghost pluck
  if istp % 7 == 4 && random(0, 100) < 30 then
    schedule "_pluck", 0.07, 0.1, 0.2
  endif

  ; Ambient accent only at the beginning of each 16-step loop
  if istp % 64 == 0 then
    schedule "_ambience", 0, 1.5
  endif
  
  ; Non-melodic beep sounds with pattern
  if table(ipatternPos, giPadPattern) > 0 then
    ; Use fixed frequencies instead of musical notes
    ifreqArr[] fillarray 440, 550, 330, 605, 275, 495
    ifreqIndex = ipatternPos % lenarray(ifreqArr)
    ifreq = ifreqArr[ifreqIndex]
    
    ; Shorter duration for beep-like character
    iBeepDur = 0.2 + random(0, 0.05)
    
    ; Randomize velocity slightly
    iBeepVel = 0.15 + random(-0.03, 0.03)
    
    ; Schedule the beep sound
    schedule "_pad", 0, iBeepDur, ifreq, iBeepVel

    
  endif
endin

; Removed _kick instrument definition

instr _bass
  ; Realtime-controlled parameters
  koct chnget "octave"
  krange chnget "range"
  kcut chnget "cutoff"
  kres chnget "resonance"
  kvol chnget "volume"
  katt chnget "attack"
  krel chnget "release"
  kpanning chnget "panning_range"
  ksend chnget "reverb_send"

  ; Bass frequency, i-time
  ifreq = cpsmidinn(koct + int(random(-krange, krange)))

  ; Filter cutoff LFO
  kcutoff lfo kcut + random(100, 200), 0.05, 1
  kcutoff = limit(kcutoff, 300, 1200)

  ; Envelope
  aenv linseg 0, katt, 1, p3 - (katt + krel), 1, krel, 0

  ; Oscillators
  asig1 oscili 0.4 * aenv, ifreq, giSin
  asig2 oscili 0.15 * aenv, ifreq * 2, giSin
  asig = asig1 + asig2

  ; Filtering
  afilt lowpass2 asig, kcutoff, kres

  ; Stereo image
  al, ar pan2 afilt, 0.5 + random(-kpanning, kpanning)

  ; Output
  outs al * kvol, ar * kvol

  ; Reverb send
  chnmix al * ksend, "fxL"
  chnmix ar * ksend, "fxR"
endin


; Removed _hat instrument definition

instr _pluck
  ; p4 = amplitude/velocity
  ; p5 = 0
  
  iamp = p4
  iReverb init 0.15  ; Initialize with a default value
  
  ; Check if a fifth parameter (reverb) was passed
  if p5 != 0 then
    iReverb = p5
  endif

  ibasefreq = 50 + random(50, 50)  ; Non-pitched percussion frequency range
  
  ; Noise excitation for percussive character
  aexcite rand 1
  aexcite butterlp aexcite, 10000
  aexcite butterhp aexcite, 1000
  
  ; Sharp attack envelope for percussion
  aenv expseg 0.001, 0.005, 1, 0.05, 0.3, p3-0.055, 0.001
  
  ; Percussive body using noise and filtered components
  anoise rand 0.7
  anoise butterbp anoise, ibasefreq, ibasefreq/5
  anoise = anoise * aenv * 0.5
  
  ; Click component for attack
  aclick expseg 1, 0.005, 0.001, 0.01, 0.0001
  aclick *= random(0.7, 1.0) * iamp
  
  ; Body resonance using pluck for short decay
  apluck pluck iamp * 5.6, ibasefreq, ibasefreq, 0, 1
  apluck butterhp apluck, 1200
  apluck *= aenv
  
  ; Combine all components
  asig = anoise + aclick + apluck
  
  ; Slight distortion for edge
  asig = tanh(asig * 1.5) * 0.8
  
  ; Apply filter modulation for texture
  kfiltmod expseg 1, 0.01, 0.7, p3-0.01, 0.5
  asig butterbp asig, ibasefreq * kfiltmod, ibasefreq/3
  
  ; Stereo positioning with more movement
  ipan = 0.5 + random(-0.3, 1.3)
  al, ar pan2 asig, ipan
  
  outs al * iamp, ar * iamp
  
  ; Less reverb for more direct, percussive sound
  chnmix al * 0.15, "fxL"
  chnmix ar * 0.15, "fxR"

  ; Use the initialized reverb amount
  chnmix al * iReverb, "fxL"
  chnmix ar * iReverb, "fxR"

  ; Simulate 3D positioning
  ; Simplified 3D-like effect
  kaz init 0  ; Azimuth angle (horizontal)
  kel init -180  ; Elevation angle (vertical)
  kdist init 2  ; Distance from listener

  ; Amplitude based on distance (inverse square law)
  kamp = 1 / (kdist * kdist)

  ; Frequency filtering to simulate distance
  asig lowpass2 asig, 600, 1

  ; Basic stereo positioning with depth simulation
  al, ar pan2 asig, 0.9  ; Positioned to right
  al *= kamp * 0.7  ; Reduce left amplitude
  ar *= kamp * 1.0  ; Full right amplitude

  ; Add subtle time delay to simulate positioning
  adl delay asig, 1.01  ; Small delay for depth perception
  adr delay asig, 1.005

  ; Output with simulated 3D characteristics
  outs al, ar
endin

instr _ambience
  ; p4 = amplitude/velocity (optional)
  ; p5 = reverb amount (optional)
  
  iamp init 1.0  ; Default amplitude
  iReverb init 0.2  ; Default reverb amount
  
  ; Check if parameters were passed
  if p4 != 0 then
    iamp = p4
  endif
  
  if p5 != 0 then
    iReverb = p5
  endif
  
  ; Basic ambience generation
  ifreq = 120
  imod = ifreq
  aenv expseg 0.001, 0.1, 0.2, p3 - 0.1, 0.001
  amod oscili imod, imod * 0.5
  asig oscili aenv, ifreq + amod
  
  ; Apply amplitude control
  asig = asig * iamp
  
  ; Simulate 3D positioning
  kaz init 0  ; Azimuth angle (horizontal)
  kel init -180  ; Elevation angle (vertical)
  kdist init 2  ; Distance from listener
  
  ; Amplitude based on distance (inverse square law)
  kamp = 8 / (kdist * kdist)
  
  ; Frequency filtering to simulate distance
  asig lowpass2 asig, 800, 0.8
  
  ; Basic stereo positioning with depth simulation
  ipan = 0.1 + random(-0.4, 0.4)  ; Keep original panning range
  al, ar pan2 asig, ipan
  
  ; Add subtle time delay to simulate positioning
  adl delay asig, 0.009  ; Small delay for depth perception
  adr delay asig, 0.005
  
  ; Blend original panning with delay for enhanced spaciousness
  al = al * 0.7 + adl * 0.3
  ar = ar * 0.7 + adr * 0.3
  
  ; Apply distance attenuation
  al *= kamp
  ar *= kamp
  
  ; Output with simulated 3D characteristics
  outs al, ar
  
  ; Send to reverb channels with specified amount
  chnmix al * iReverb, "fxL"
  chnmix ar * iReverb, "fxR"
endin

instr _pad
  ; p4 = frequency (optional)
  ; p5 = amplitude/velocity (optional)
  
  ; Set default frequency if not provided
  ifreq init 440
  if p4 != 0 then
    ifreq = p4
  endif
  
  iamp init 0.15  ; Default amplitude
  if p5 != 0 then
    iamp = p5
  endif
  
  ; Create a non-melodic beep sound
  
  ; Short envelope for beep character
  aenv linseg 0, 0.01, 1, 0.08, 0.7, 0.1, 0
  
  ; Simple sine oscillator for clean beep
  aosc oscili aenv, ifreq, giSin
  
  ; Add some noise component for less tonal character
  anoise rand aenv * 0.2
  anoise butterbp anoise, ifreq, ifreq/4
  
  ; Combine signals
  asig = aosc + anoise
  
  ; Apply bandpass filter to shape the tone
  afilt butterbp asig, ifreq, ifreq/3
  
  ; Simple stereo spread
  aleft, aright pan2 afilt, 0.5 + random(-0.3, 0.3)
  
  ; Output to speakers
  outs aleft * iamp, aright * iamp
  
  ; Minimal reverb
  chnmix aleft * 0.1, "fxL"
  chnmix aright * 0.1, "fxR"
endin

instr fx_reverb
  aL chnget "fxL"
  aR chnget "fxR"
  arL, arR reverbsc aL, aR, 0.9, 12000
  outs arL, arR
  chnclear "fxL", "fxR"
endin

</CsInstruments>

<CsScore>
f 0 3600  ; 1-hour continuous session
</CsScore>

</CsoundSynthesizer>
<bsbPanel>
 <label>Widgets</label>
 <objectName/>
 <x>100</x>
 <y>100</y>
 <width>320</width>
 <height>240</height>
 <visible>true</visible>
 <uuid/>
 <bgcolor mode="background">
  <r>240</r>
  <g>240</g>
  <b>240</b>
 </bgcolor>
</bsbPanel>
<bsbPresets>
</bsbPresets>