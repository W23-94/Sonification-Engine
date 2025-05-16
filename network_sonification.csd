
<CsoundSynthesizer>
<CsOptions>
-odac
</CsOptions>
<CsInstruments>

sr = 44100
ksmps = 32
nchnls = 2
0dbfs = 1

; Global reverb
gaRevL init 0
gaRevR init 0

; Protocol-specific instruments
; TCP - more percussive (port 1)
instr 1
    ; Base frequency determined by destination port
    ifreq = 100 + (p4 * 0.5)
    ; Volume based on priority
    iamp = p5 * 0.2
    ; Duration
    idur = p3
    
    ; Envelope
    aenv linen iamp, 0.01, idur, 0.1
    
    ; Percussive sound for TCP
    a1 pluck aenv, ifreq, ifreq, 0, 1
    a2 moogvcf a1, ifreq*3, 0.7
    
    ; Output
    outs a2*aenv, a2*aenv
    
    ; Send to reverb
    gaRevL = gaRevL + a2*aenv*0.1
    gaRevR = gaRevR + a2*aenv*0.1
endin

; UDP - more airy (port 2)
instr 2
    ifreq = 200 + (p4 * 0.3)
    iamp = p5 * 0.15
    idur = p3
    
    ; Envelope
    aenv linen iamp, 0.05, idur, 0.2
    
    ; More "airy" sound for UDP
    a1 foscili aenv, ifreq, 1, 2.5, 3, 1
    a2 butterlp a1, 2000
    
    ; Output
    outs a2, a2
    
    ; Send to reverb
    gaRevL = gaRevL + a2*0.2
    gaRevR = gaRevR + a2*0.2
endin

; ICMP - ping sound (port 3)
instr 3
    ifreq = 300 + (p4 * 0.2)
    iamp = p5 * 0.25
    idur = p3
    
    ; Quick envelope for ping
    aenv expon iamp, idur, 0.001
    
    ; Simple sine for ping
    a1 oscili aenv, ifreq
    a2 oscili aenv, ifreq*1.5
    
    ; Output
    outs a1+a2*0.5, a1+a2*0.5
    
    ; Send to reverb
    gaRevL = gaRevL + (a1+a2*0.5)*0.15
    gaRevR = gaRevR + (a1+a2*0.5)*0.15
endin

; Alert - distinctive warning sound (port 4)
instr 4
    ifreq = 400
    iamp = p4 * 0.3
    
    ; Pulsing envelope for alerts
    kenv lfo iamp, 8, 0
    kenv = abs(kenv) + 0.1
    
    ; Alert sound
    a1 foscili kenv, ifreq, 1, 1.5, 2.5
    a2 foscili kenv, ifreq*1.33, 1, 1.5, 1.5
    
    ; Mix
    a3 = a1 + a2*0.7
    
    ; Output
    outs a3, a3
    
    ; Send to reverb
    gaRevL = gaRevL + a3*0.3
    gaRevR = gaRevR + a3*0.3
endin

; Background traffic hum (port 5)
instr 5
    ifreq = 60
    iamp = p4 * 0.05
    
    ; Slow LFO modulation
    kmod lfo 30, 0.1, 0
    
    ; Ambient hum
    a1 oscili iamp, ifreq + kmod
    a2 oscili iamp*0.5, ifreq*2 + kmod*2
    
    ; Output
    outs a1+a2*0.3, a1+a2*0.3
endin

; Reverb instrument
instr 99
    aL, aR reverbsc gaRevL, gaRevR, 0.85, 10000
    outs aL, aR
    clear gaRevL, gaRevR
endin

</CsInstruments>
<CsScore>
; Start the reverb
i 99 0 3600
; Background hum
i 5 0 3600 1
</CsScore>
</CsoundSynthesizer>
