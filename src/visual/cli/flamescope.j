blip =
    fn (time)
        o = 
            object
                'time : time
                'count : 0
        o
newest-blip = (' (heatmap ((len heatmap) - 1)) )

interval-time     := 0.02
heatmap-start-row := 5
heatmap-start-col := 1
heatmap-height    := (sint (1 / interval-time))

# Colors
heatmap-select-start-color := 0x00ff00
heatmap-select-end-color := 0x0000ff

heatmap-on-click =
    fn (&rect row col)
        (&rect 'color) = 0x00ff00
        ((&rect 'paint-fn)) &rect
        @term:flush
        
prev-hover-been-set := 0
prev-hover-color := 0x000000

heatmap-on-hover =
    fn (&rect row col)
        # Color the new rectangle
        color = (&rect 'color)
        (&rect 'color) = 0x00ff00
        ((&rect 'paint-fn)) &rect
        @term:flush
        
        # Recolor the previously-highlighted one
        if (prev-hover-been-set)
            (&prev-hover 'color) = prev-hover-color
            ((&prev-hover 'paint-fn)) &prev-hover
            @term:flush
            unref &prev-hover
        
        &prev-hover := &rect
        prev-hover-color := color
        prev-hover-been-set := 1

parse-heatmap-input =
    fn ()
        f = (fopen-rd ((argv) 1))
        lines = (fread-lines f)
        length = (len lines)
        
        # Loading bar for loading the input file
        add-element
            loading-bar 1 "PROFILE"
        &profile-bar = (newest-element)
        loading-bar-update &profile-bar 0.0
        
        # Loading bar for loading the heatmap
        add-element
            loading-bar 2 "HEATMAP"
        &heatmap-bar = (newest-element)
        loading-bar-update &heatmap-bar 0.0
        
        heatmap = (list)
        
        index = 0
        largest-count = 0
        total-count = 0
        cur-time = 0
        foreach &line lines
            split-line = (split &line "\t")
            event = (split-line 0)
            match event
                "e"
                    count = (parse-int (split-line 3))
                    (&cur-blip 'count) += count
                    total-count += count
                    
                "interval_start"
                
                    time = (parse-float (split-line 2))
                    
                    # Initial blip
                    if (cur-time == 0)
                        cur-time = time
                        append heatmap
                            blip cur-time
                        &cur-blip = (newest-blip)
                        
                    # Should we create more blips?
                    if (time >= (cur-time + interval-time))
                    
                        # Update largest-count
                        if ((&cur-blip 'count) > largest-count)
                            largest-count = (&cur-blip 'count)
                            
                        # Create num-elapsed blips
                        num-elapsed = (sint ((time - cur-time) / interval-time))
                        repeat i num-elapsed
                            append heatmap
                                blip (cur-time + (interval-time * (i + 1)))
                        cur-time += (interval-time * num-elapsed)
                        
                        # Update cur-blip
                        unref &cur-blip
                        &cur-blip = (newest-blip)
                            
            if ((index % 10000) == 0)
                loading-bar-update &profile-bar ((float index) / length)
                
            index += 1
            
        loading-bar-update &profile-bar 1.0
        append elements
            text 3 1 (fmt "Total Samples: %" total-count) ('color : 0xffffff)
        append elements
            text 4 1 (fmt "# Intervals: %" (len heatmap)) ('color : 0xffffff)
        paint
        
        index = 0
        row = (heatmap-start-row + (heatmap-height - 1))
        col = heatmap-start-col
        length = (len heatmap)
        foreach &blip heatmap
            value = ((float (&blip 'count)) / largest-count)
            append elements
                rect row col 1 1 (select (value == 0.0) 0x000000 ((sint ((value * 225) + 30)) << 16))
                    'on-click : heatmap-on-click
                    'on-hover : heatmap-on-hover
            if (row == heatmap-start-row)
                col += 1
                row = (heatmap-start-row + (heatmap-height - 1))
            else
                row -= 1
            
            if ((col % 50) == 0)
                loading-bar-update &heatmap-bar ((float index) / length)
            index += 1
        loading-bar-update &heatmap-bar 1.0
        paint
            
        fclose f
        
key-actions =
    object
        "q" : (' (@term:exit) )

@on-key =
    fn (key)
        if (key in key-actions)
            (key-actions key)

@on-mouse =
    fn (type action button row col)
        if ((action == 'down) and (button == 'left))
          foreach &elem elements
              if (('on-click in &elem) and (in-element &elem row col))
                  (&elem 'on-click) &elem row col
        elif (action == 'over)
          foreach &elem elements
              if (('on-hover in &elem) and (in-element &elem row col))
                  (&elem 'on-hover) &elem row col

redraw =
    fn (rows cols)
        rows := rows
        cols := cols
        elements := (list)
        paint

@on-init =
    fn (rows cols)
        redraw rows cols
        elements := (list)
        paint
        parse-heatmap-input
