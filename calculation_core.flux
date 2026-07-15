NODE main_hadron_ring { path_geometry: DENDRITE_HEX; base_resistance: 50.0_OHM; }

COMPUTE run_accelerator() {
    INJECT main_hadron_ring ;
}

REVERSE recover_energy() {
    EXTRACT main_hadron_ring ;
}

