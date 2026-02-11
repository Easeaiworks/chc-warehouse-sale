const fs = require('fs');

// All products from the original hardcoded data
const PRODUCTS = {
  "3M": {
    hasCategories: true,
    categories: {
      "Abrasives & Sanding": [
        { sku: "MMM02021", name: "3M Wetordry Abrasive Sheet P1000", previousPrice: "85.99", salePrice: "64.99" },
        { sku: "MMM02022", name: "3M Wetordry Abrasive Sheet P1200", previousPrice: "74.99", salePrice: "64.99" },
        { sku: "MMM02023", name: "3M Wetordry Abrasive Sheet P1500", previousPrice: "74.99", salePrice: "64.99" },
        { sku: "MMM02035", name: "3M Wetordry Abrasive Sheet P800", previousPrice: "85.99", salePrice: "69.99" },
        { sku: "MMM02036", name: "3M Wetordry Abrasive Sheet P600", previousPrice: "85.99", salePrice: "69.99" },
        { sku: "MMM02038", name: "3M Wetordry Abrasive Sheet P400", previousPrice: "85.99", salePrice: "69.99" },
        { sku: "MMM02044", name: "3M Wetordry Abrasive Sheet P2000", previousPrice: "85.99", salePrice: "64.99" },
        { sku: "MMM02045", name: "3M Wetordry Abrasive Sheet P2500", previousPrice: "85.99", salePrice: "64.99" },
        { sku: "MMM02085", name: "3M 6in Trizact Hookit Foam Disc P3000", previousPrice: "180.99", salePrice: "139.99" },
        { sku: "MMM02087", name: "3M 3in Trizact Hookit Foam Disc P3000", previousPrice: "91.99", salePrice: "74.99" },
        { sku: "MMM30662", name: "3M Trizact Hookit Foam Disc P5000 6in", previousPrice: "159.99", salePrice: "109.99" },
        { sku: "MMM30666", name: "3M Hookit Purple Finishing Film Disc 6in P2000", previousPrice: "79.99", salePrice: "64.99" },
        { sku: "MMM31370", name: "3M Cubitron II Hookit Abrasive Disc P40 6in", previousPrice: "95.99", salePrice: "79.99" },
        { sku: "MMM31371", name: "3M Cubitron II Hookit Abrasive Disc P80 6in", previousPrice: "79.99", salePrice: "59.99" },
        { sku: "MMM31372", name: "3M Cubitron II Hookit Abrasive Disc P120 6in", previousPrice: "79.99", salePrice: "59.99" },
        { sku: "MMM31373", name: "3M Cubitron II Hookit Abrasive Disc P150 6in", previousPrice: "79.99", salePrice: "59.99" },
        { sku: "MMM33538", name: "3M Hookit Flexible Foam Abrasive Disc P400 6in", previousPrice: "52.99", salePrice: "39.99" },
        { sku: "MMM33539", name: "3M Hookit Flexible Foam Abrasive Disc P600 6in", previousPrice: "52.99", salePrice: "39.99" },
        { sku: "MMM36170", name: "3M Hookit Blue Disc P40 6in", previousPrice: "58.99", salePrice: "49.99" },
        { sku: "MMM36172", name: "3M Hookit Blue Disc P80 6in", previousPrice: "63.99", salePrice: "49.99" },
        { sku: "MMM36174", name: "3M Hookit Blue Disc P120 6in", previousPrice: "58.99", salePrice: "49.99" },
        { sku: "MMM36176", name: "3M Hookit Blue Disc P180 6in", previousPrice: "58.99", salePrice: "49.99" },
        { sku: "MMM36180", name: "3M Hookit Blue Disc P320 6in", previousPrice: "58.99", salePrice: "49.99" },
      ],
      "Polishing & Compounding": [
        { sku: "MMM05706", name: "3M Perfect-It Foam Compounding Pad", previousPrice: "63.99", salePrice: "29.99" },
        { sku: "MMM05707", name: "3M Perfect-It Foam Polishing Pad", previousPrice: "58.99", salePrice: "35.99" },
        { sku: "MMM05708", name: "3M Perfect-It Ultrafine Foam Polishing Pad", previousPrice: "58.99", salePrice: "39.99" },
        { sku: "MMM06068", name: "3M Perfect-It Ultrafine Machine Polish 946mL", previousPrice: "74.99", salePrice: "69.99" },
        { sku: "MMM06094", name: "3M Perfect-It Machine Polish", previousPrice: "85.99", salePrice: "69.99" },
        { sku: "MMM33279", name: "3M Perfect-It Low Linting Wool Pad", previousPrice: "79.99", salePrice: "59.99" },
        { sku: "MMM36060", name: "3M Perfect-It EX Rubbing Compound Qt", previousPrice: "74.99", salePrice: "59.99" },
      ],
      "Body Fillers & Repair": [
        { sku: "MMM01131", name: "3M Platinum Plus Body Filler Ga", previousPrice: "71.99", salePrice: "69.99", promo: "Buy 3 Gallons Get 1 Gallon Free" },
        { sku: "MMM04240", name: "3M Semi-Rigid Plastic Repair 200mL", previousPrice: "79.99", salePrice: "59.99" },
        { sku: "MMM04247", name: "3M Super Fast Plastic Repair 200mL", previousPrice: "90.99", salePrice: "69.99" },
        { sku: "MMM04248", name: "3M Super Fast Repair Adhesive 200mL", previousPrice: "100.99", salePrice: "74.99" },
        { sku: "MMM05887", name: "3M EZ Sand Flexible Parts Repair Adhesive", previousPrice: "110.99", salePrice: "79.99" },
        { sku: "MMM05860", name: "3M Dry Guide Coat Cartridge", previousPrice: "53.99", salePrice: "44.99", promo: "Buy 2 Cases Get 1 Free" },
        { sku: "MMM05861", name: "3M Dry Guide Coat Applicator Kit", previousPrice: "79.99", salePrice: "64.99" },
        { sku: "MMM20382", name: "3M Disposable Paper Mixing Board", previousPrice: "37.99", salePrice: "29.99" },
      ],
      "Adhesives & Seam Sealers": [
        { sku: "MMM07333", name: "3M Impact Resistant Structural Adhesive 200mL", previousPrice: "160.99", salePrice: "99.99" },
        { sku: "MMM08115", name: "3M Automix Panel Bonding Adhesive 200mL", previousPrice: "101.99", salePrice: "79.99" },
        { sku: "MMM08194", name: "3M Static Mix Nozzles", previousPrice: "148.99", salePrice: "109.99" },
        { sku: "MMM08308", name: "3M Heavy-Bodied Seam Sealer 200mL", previousPrice: "74.99", salePrice: "59.99" },
        { sku: "MMM08323", name: "3M Factory Match Seam Sealer 200mL", previousPrice: "76.99", salePrice: "49.99" },
        { sku: "MMM08522", name: "3M OEM Match Epoxy Seam Sealer Beige", previousPrice: "97.99", salePrice: "57.99" },
        { sku: "MMM08524", name: "3M OEM Match Epoxy Seam Sealer White", previousPrice: "97.99", salePrice: "57.99" },
        { sku: "MMM08526", name: "3M OEM Match Epoxy Seam Sealer Gray", previousPrice: "97.99", salePrice: "57.99" },
        { sku: "MMM08528", name: "3M OEM Match Epoxy Seam Sealer Black", previousPrice: "97.99", salePrice: "57.99" },
        { sku: "MMM08852", name: "3M Cavity Wax Plus 511g", previousPrice: "42.99", salePrice: "42.99", promo: "Buy 2 Cases Get 1 Free" },
        { sku: "MMM06382", name: "3M Two Way Acrylic Plus Tape 1/2in", previousPrice: "73.99", salePrice: "49.99" },
        { sku: "MMM06383", name: "3M Two Way Acrylic Plus Tape 7/8in", previousPrice: "107.99", salePrice: "69.99" },
        { sku: "MMM06386", name: "3M Two Way Acrylic Plus Tape 1/4in", previousPrice: "61.99", salePrice: "29.99" },
      ],
      "Masking & Surface Protection": [
        { sku: "MMM06349", name: "3M Trim & Lift Masking Tape", previousPrice: "63.99", salePrice: "39.99" },
        { sku: "MMM06652", name: "3M Yellow Masking Tape 18mm", previousPrice: "159.99", salePrice: "119.99" },
        { sku: "MMM06654", name: "3M Yellow Masking Tape 36mm", previousPrice: "159.99", salePrice: "119.99" },
        { sku: "MMM06656", name: "3M Yellow Masking Tape 48mm", previousPrice: "191.99", salePrice: "129.99" },
        { sku: "MMM06718", name: "3M Scotchblok Masking Paper", previousPrice: "74.99", salePrice: "64.99" },
        { sku: "MMM06724", name: "3M Plastic Sheeting 16x350ft", previousPrice: "58.99", salePrice: "33.99" },
        { sku: "MMM26334", name: "3M Scotch Green Masking Tape 3/4in", previousPrice: "244.99", salePrice: "169.99" },
        { sku: "MMM26338", name: "3M Scotch Green Masking Tape 1 1/2in", previousPrice: "138.99", salePrice: "99.99" },
        { sku: "MMM36852", name: "3M Dirt Trap Protection Material 28in", previousPrice: "668.99", salePrice: "499.99" },
        { sku: "MMM05916", name: "3M Welding and Spark Deflection Paper", previousPrice: "244.99", salePrice: "149.99" },
        { sku: "MMM05917", name: "3M Weld-Thru Coating II", previousPrice: "47.99", salePrice: "39.99" },
        { sku: "MMM07847", name: "3M Scotch-Brite Red Durable Flex Pads", previousPrice: "37.99", salePrice: "37.99", promo: "Buy 2 Cases Get 1 Free" },
        { sku: "MMM07848", name: "3M Scotch-Brite Grey Durable Flex Pads", previousPrice: "37.99", salePrice: "37.99", promo: "Buy 2 Cases Get 1 Free" },
      ],
      "Spray Guns & PPS Systems": [
        { sku: "MMM26000", name: "3M PPS Series 2.0 Standard", previousPrice: "169.99", salePrice: "119.99" },
        { sku: "MMM26024", name: "3M PPS Spray Cup Large", previousPrice: "175.99", salePrice: "124.99" },
        { sku: "MMM26112", name: "3M PPS 2.0 Kit", previousPrice: "175.99", salePrice: "109.99" },
        { sku: "MMM26114", name: "3M PPS 2.0 Mini Kit", previousPrice: "159.99", salePrice: "99.99" },
        { sku: "MMM26163", name: "3M PPS 2.0 Vented Cups Standard", previousPrice: "201.99", salePrice: "69.99" },
        { sku: "MMM26164", name: "3M PPS 2.0 Vented Large Cups", previousPrice: "201.99", salePrice: "89.99" },
        { sku: "MMM26301", name: "3M PPS 2.0 Medium Lids & Liners", previousPrice: "169.99", salePrice: "119.99" },
        { sku: "MMM26689", name: "3M High Power Spray Gun Cleaner", previousPrice: "16.99", salePrice: "16.99", promo: "Buy 2 Cases Get 1 Free" },
        { sku: "MMM26832", name: "3M Performance Spray Gun", previousPrice: "488.99", salePrice: "399.99" },
        { sku: "MMM26712", name: "3M HVLP Atomizing Head Refill Kit 1.2", previousPrice: "53.99", salePrice: "49.99" },
        { sku: "MMM26713", name: "3M HVLP Atomizing Head Refill Kit 1.3", previousPrice: "53.99", salePrice: "49.99" },
        { sku: "MMM26714", name: "3M HVLP Atomizing Head Refill Kit 1.4", previousPrice: "53.99", salePrice: "49.99" },
      ],
    }
  },
  "SEM": {
    hasCategories: true,
    categories: {
      "Seam Sealers": [
        { sku: "SEM29362", name: "SEM 1K SEAM SEALER - WHITE", previousPrice: "30.99", salePrice: "27.99" },
        { sku: "SEM29372", name: "SEM 1K SEAM SEALER - GRAY", previousPrice: "30.99", salePrice: "27.99" },
        { sku: "SEM29382", name: "SEM 1K SEAM SEALER - BEIGE", previousPrice: "30.99", salePrice: "27.99" },
        { sku: "SEM29392", name: "SEM 1K SEAM SEALER - BLACK", previousPrice: "30.99", salePrice: "27.99" },
        { sku: "SEM29462", name: "SEM 2-IN-1 SEAM SEALER - WHITE", previousPrice: "34.99", salePrice: "29.99" },
        { sku: "SEM29472", name: "SEM 2-IN-1 SEAM SEALER - GRAY", previousPrice: "34.99", salePrice: "29.99" },
        { sku: "SEM29482", name: "SEM 2-IN-1 SEAM SEALER - BEIGE", previousPrice: "34.99", salePrice: "29.99" },
        { sku: "SEM29492", name: "SEM 2-IN-1 SEAM SEALER - BLACK", previousPrice: "34.99", salePrice: "29.99" },
      ],
      "Primers & Coatings": [
        { sku: "SEM39143", name: "SEM TRIM BLACK", previousPrice: "24.99", salePrice: "19.99" },
        { sku: "SEM39144-LV", name: "SEM LOW VOC TRIM BLACK", previousPrice: "87.99", salePrice: "69.99" },
        { sku: "SEM39673", name: "SEM SELF ETCHING PRIMER - BLACK", previousPrice: "37.99", salePrice: "29.99" },
        { sku: "SEM39683", name: "SEM SELF ETCHING PRIMER - GRAY", previousPrice: "37.99", salePrice: "29.99" },
        { sku: "SEM39863", name: "SEM PLASTIC ADHESION PROMOTER", previousPrice: "45.99", salePrice: "39.99" },
        { sku: "SEM40773", name: "SEM ZINCWELD", previousPrice: "39.99", salePrice: "34.99" },
        { sku: "SEM62213", name: "SEM EZ COAT - BLACK", previousPrice: "30.99", salePrice: "24.99" },
        { sku: "SEM62243", name: "SEM EZ COAT - GRAY", previousPrice: "30.99", salePrice: "24.99" },
      ],
      "Body Fillers & Glazes": [
        { sku: "SEM40561", name: "SEM Powder Pro Ultra Lightweight Body Filler", previousPrice: "99.99", salePrice: "79.99" },
        { sku: "SEM39592", name: "SEM METAL BITE FINISHING GLAZE", previousPrice: "66.99", salePrice: "54.99" },
        { sku: "SEM40482", name: "SEM BUMPER BITE FLEXIBLE GLAZE", previousPrice: "55.99", salePrice: "44.99" },
      ],
      "Bed Liners & Protective Coatings": [
        { sku: "SEM56650", name: "SEM GLADIATOR XC BLACK KIT", previousPrice: "243.99", salePrice: "199.99" },
        { sku: "SEM56670", name: "SEM GLADIATOR XC TINTABLE KIT", previousPrice: "243.99", salePrice: "199.99" },
      ],
      "Abrasives": [
        { sku: "SA6080", name: "SEM 6\" Grip Multihole 80, 50 Discs/Box", previousPrice: "67.99", salePrice: "59.99" },
        { sku: "SA6120", name: "SEM 6\" Grip Multihole 120, 50 Discs/Box", previousPrice: "69.99", salePrice: "49.99" },
        { sku: "SA6180", name: "SEM 6\" Grip Multihole 180, 50 Discs/Box", previousPrice: "69.99", salePrice: "49.99" },
        { sku: "SA6240", name: "SEM 6\" Grip Multihole 240, 50 Discs/Box", previousPrice: "69.99", salePrice: "49.99" },
        { sku: "SA6320", name: "SEM 6\" Grip Multihole 320, 50 Discs/Box", previousPrice: "69.99", salePrice: "49.99" },
        { sku: "SA6400", name: "SEM 6\" Grip Multihole 400, 50 Discs/Box", previousPrice: "69.99", salePrice: "49.99" },
      ],
      "Aerosols & Specialty": [
        { sku: "SEM61993", name: "SEM CUSTOM FILL AEROSOL BLANK", previousPrice: "60.00", salePrice: "24.99" },
      ],
    }
  },
  "PPG": {
    hasCategories: true,
    categories: {
      "Clearcoats": [
        { sku: "EC520", name: "EHP High Production Clearcoat Ga", previousPrice: "816.20", salePrice: "408.10" },
        { sku: "EC530", name: "EHP Performance Clearcoat Ga", previousPrice: "816.20", salePrice: "408.10" },
        { sku: "EC550", name: "EHP Ultra Gloss Clearcoat Ga", previousPrice: "816.20", salePrice: "408.10" },
        { sku: "UT500", name: "Envirobase High Clarity Clearcoat Ga", previousPrice: "787.20", salePrice: "393.60" },
        { sku: "UT501", name: "Envirobase Low Gloss Clearcoat Ga", previousPrice: "787.20", salePrice: "393.60" },
        { sku: "UT502", name: "Envirobase Ultra High Clarity Clearcoat Ga", previousPrice: "885.20", salePrice: "442.60" },
      ],
      "Base Coats": [
        { sku: "BC600", name: "EHP Pearl White Base Qa", previousPrice: "695.20", salePrice: "347.60" },
        { sku: "BC700", name: "EHP Metallic Black Base Qa", previousPrice: "745.20", salePrice: "372.60" },
        { sku: "BT100", name: "Envirobase Pearl White Base Qa", previousPrice: "625.40", salePrice: "312.70" },
        { sku: "BT200", name: "Envirobase Metallic Silver Base Qa", previousPrice: "675.50", salePrice: "337.75" },
      ],
      "Primers & Surfacers": [
        { sku: "AP200", name: "Acrylic Surfacer Red Qa", previousPrice: "545.90", salePrice: "272.95" },
        { sku: "AP300", name: "Acrylic Primer Sealer Qa", previousPrice: "512.10", salePrice: "256.05" },
        { sku: "EP400", name: "Epoxy Primer Gray Ga", previousPrice: "678.20", salePrice: "339.10" },
        { sku: "EP500", name: "Urethane Primer Gray Ga", previousPrice: "612.30", salePrice: "306.15" },
      ],
    }
  },
  "Tamco": {
    hasCategories: true,
    categories: {
      "Clearcoats": [
        { sku: "TAM900", name: "Tamco 2K Clearcoat Ga", previousPrice: "520.00", salePrice: "260.00" },
        { sku: "TAM950", name: "Tamco UHS Clearcoat Ga", previousPrice: "595.00", salePrice: "297.50" },
      ],
      "Base Coats": [
        { sku: "TAM100", name: "Tamco Pearl Base Coat Qa", previousPrice: "450.00", salePrice: "225.00" },
        { sku: "TAM200", name: "Tamco Metallic Base Coat Qa", previousPrice: "485.00", salePrice: "242.50" },
      ],
      "Primers": [
        { sku: "TAM500", name: "Tamco Epoxy Primer Ga", previousPrice: "410.00", salePrice: "205.00" },
        { sku: "TAM600", name: "Tamco Urethane Primer Ga", previousPrice: "385.00", salePrice: "192.50" },
      ],
    }
  },
  "Dupli-Color": {
    hasCategories: false,
    products: [
      { sku: "DC001", name: "Dupli-Color Trim & Bumper Coating", previousPrice: "18.99", salePrice: "12.99" },
      { sku: "DC002", name: "Dupli-Color Plastic Adhesion Promoter", previousPrice: "21.99", salePrice: "14.99" },
      { sku: "DC003", name: "Dupli-Color Heavy-Duty Rubberized Undercoat", previousPrice: "24.99", salePrice: "16.99" },
      { sku: "DC004", name: "Dupli-Color Engine Enamel Gloss Black", previousPrice: "16.99", salePrice: "10.99" },
      { sku: "DC005", name: "Dupli-Color Acrylic Enamel Gloss White", previousPrice: "16.99", salePrice: "10.99" },
      { sku: "DC006", name: "Dupli-Color Acrylic Enamel Gloss Red", previousPrice: "16.99", salePrice: "10.99" },
    ]
  },
  "Henkel": {
    hasCategories: true,
    categories: {
      "Adhesives & Sealants": [
        { sku: "HEN2568787", name: "Henkel Teroson PU 8590 Panel Bond Adhesive", previousPrice: "72.99", salePrice: "54.99" },
        { sku: "HEN2568797", name: "Henkel Teroson MS 222 Anti-Flutter Material", previousPrice: "44.99", salePrice: "29.99" },
        { sku: "HEN2568817", name: "Henkel Teroson MS 9120 SF - White", previousPrice: "37.99", salePrice: "24.99" },
        { sku: "HEN2568818", name: "Henkel Teroson MS 9320 SF - Grey", previousPrice: "37.99", salePrice: "24.99" },
        { sku: "HEN2816502", name: "Henkel Teroson EP 5055 SB Panel Bond Adhesive", previousPrice: "91.99", salePrice: "49.99" },
        { sku: "HEN2820041", name: "Henkel Teroson MS 9320 SF - Black", previousPrice: "37.99", salePrice: "24.99" },
        { sku: "HEN1434516", name: "Henkel Loctite Replacement Nozzles", previousPrice: "7.99", salePrice: "5.99" },
        { sku: "HEN1585815", name: "Henkel Teroson ET UBC Gun", previousPrice: "60.99", salePrice: "54.99" },
      ]
    }
  },
  "Q1": {
    hasCategories: false,
    products: [
      { sku: "CPM118", name: "Q1 Car Plus Masking Tape 18mm (3/4\")", previousPrice: "75.00", salePrice: "65.00" },
      { sku: "CPM136.55", name: "Q1 Car Plus Masking Tape 36mm (1 1/2\")", previousPrice: "75.00", salePrice: "65.00" },
    ]
  },
  "Rexall": {
    hasCategories: false,
    products: [
      { sku: "CHC590248-5", name: "Premium Solvent Cleaner", previousPrice: "75.00", salePrice: "49.99" },
      { sku: "CHC590266-5", name: "Professional Solvent Cleaner", previousPrice: "59.99", salePrice: "39.99" },
      { sku: "CHC590269-5", name: "Wax and Grease Remover 5Ga", previousPrice: "135.99", salePrice: "79.99" },
      { sku: "CHC590353-5", name: "Final Wash 5Ga", previousPrice: "99.99", salePrice: "79.99" },
      { sku: "MTN0002", name: "Montana Stone Shield 400ml", previousPrice: "13.49", salePrice: "9.99" },
      { sku: "MTN0901", name: "Montana Matte Black 400ml", previousPrice: "12.49", salePrice: "7.99" },
      { sku: "MTN0903", name: "Montana Satin Black 400ml", previousPrice: "12.49", salePrice: "7.99" },
      { sku: "MTN0908", name: "Montana Gloss Acrylic 400ml", previousPrice: "15.49", salePrice: "11.99" },
      { sku: "MTN9010", name: "Montana Gloss White 400ml", previousPrice: "12.49", salePrice: "7.99" },
      { sku: "MTN9011", name: "Montana Gloss Black 400ml", previousPrice: "12.49", salePrice: "7.99" },
    ]
  },
  "Tork": {
    hasCategories: false,
    products: [
      { sku: "SCA121202", name: "8.25'x 600' M-Torq 6/pkg", previousPrice: "65.00", salePrice: "49.99" },
      { sku: "SCA192480", name: "Specialist Cloth Top Pack", previousPrice: "159.99", salePrice: "119.99" },
    ]
  },
  "Wipeco": {
    hasCategories: false,
    products: [
      { sku: "DN106-L", name: "WIPECO 6 Mil Nitrile Gloves L 100/BX", previousPrice: "15.00", salePrice: "8.99" },
      { sku: "DN106-M", name: "WIPECO 6 Mil Nitrile Gloves M 100/Bx", previousPrice: "15.00", salePrice: "8.99" },
      { sku: "DN106-XL", name: "WIPECO 6 Mil Nitrile Gloves XL 100/Bx", previousPrice: "15.00", salePrice: "8.99" },
      { sku: "DN850BKEC-L", name: "WIPECO 8 Mil Nitrile Gloves L 50/Bx", previousPrice: "15.00", salePrice: "6.99" },
      { sku: "DN850BKEC-M", name: "WIPECO 8 Mil Nitrile Gloves M 50/Bx", previousPrice: "15.00", salePrice: "6.99" },
      { sku: "DN850BKEC-XL", name: "WIPECO 8 Mil Nitrile Gloves XL 50/Bx", previousPrice: "15.00", salePrice: "6.99" },
    ]
  },
};

// Flatten and write CSV
const rows = [];
rows.push('sku,brand,category,name,previous_price,sale_price,promo');

Object.entries(PRODUCTS).forEach(([brand, data]) => {
  if (data.hasCategories) {
    Object.entries(data.categories).forEach(([category, products]) => {
      products.forEach(p => {
        rows.push(`"${p.sku}","${brand}","${category}","${p.name.replace(/"/g, '""')}",${p.previousPrice},${p.salePrice},"${(p.promo || '').replace(/"/g, '""')}"`);
      });
    });
  } else {
    (data.products || []).forEach(p => {
      rows.push(`"${p.sku}","${brand}","","${p.name.replace(/"/g, '""')}",${p.previousPrice},${p.salePrice},"${(p.promo || '').replace(/"/g, '""')}"`);
    });
  }
});

fs.writeFileSync('warehouse-sale-2026-products.csv', rows.join('\n'));
console.log(`Exported ${rows.length - 1} products to warehouse-sale-2026-products.csv`);
