### DRAWING ###
rows     = 0
cols     = 0
elements = (list)

paint =
    fn ()
        @term:clear
        foreach &element elements
            ((&element 'paint-fn)) &element
        @term:flush

add-element    = (fn (elem) (append elements elem))
newest-element = (' (elements ((len elements) - 1)) )

text =
    fn (row col s ...)
        o =
            object
                'type     : 'rect
                'paint-fn : (' paint-text)
                'row      : row
                'col      : col
                's        : s
        foreach arg ... (o <- arg)
        o

paint-text =
    fn (&text)
        row    = (&text 'row)
        col    = (&text 'col)
        tcolor = (select ('color in &text) (&text 'color) nil)
        foreach char (chars (&text 's))
            if (tcolor != nil)
                @term:set-cell-fg row col tcolor
            @term:set-cell-char row col char
            col += 1

rect =
    fn (row col height width color ...)
        o =
            object
                'type     : 'rect
                'paint-fn : (' paint-rect)
                'row      : row
                'col      : col
                'height   : height
                'width    : width
                'color    : color
        foreach arg ... (o <- arg)
        o

paint-rect =
    fn (&rect)
        &r     = (&rect 'row)
        &c     = (&rect 'col)
        &h     = (&rect 'height)
        &w     = (&rect 'width)
        &color = (&rect 'color)

        repeat r &h
            r += &r
            repeat c &w
                c += &c
                @term:set-cell-bg r c &color
        if ('text in &rect)
            c = &c
            tcolor = (select ('text-color in &rect) (&rect 'text-color) nil)
            foreach char (chars (&rect 'text))
                if (tcolor != nil)
                    @term:set-cell-fg &r c tcolor
                @term:set-cell-char &r c char
                c += 1

in-element =
    fn (&element row col)
        select ((&element 'type) == 'rect)
            and
                row >= (&element 'row)
                row  < ((&element 'row) + (&element 'height))
                col >= (&element 'col)
                col  < ((&element 'col) + (&element 'width))
            0
            
paint-loading-bar =
    fn (&loading-bar)
        foreach &element (&loading-bar 'elements)
            ((&element 'paint-fn)) &element
        foreach &element (&loading-bar 'text)
            ((&element 'paint-fn)) &element

loading-bar =
    fn (row thing ...)
        o =
            object
                'row      : row
                'thing    : thing
                'width    : 0
                'elements : (list)
                'paint-fn : (' paint-loading-bar)
                'text     : (list)
        foreach arg ... (o <- arg)
        o

loading-bar-text-push =
    fn (&loading-bar ratio)
        width = (sint (ratio * cols))
        loading-text =
            fmt
                "LOADING % %\%"
                &loading-bar 'thing
                sint (ratio * 100)
        characters = (chars loading-text)
        length = (len loading-text)
        
        index = 1
        foreach character characters
            color = 0xffffff
            if (index <= width)
                color = 0x000000
            append
                &loading-bar 'text
                text
                    &loading-bar 'row
                    index
                    character
                    'color : color
            index += 1
        
loading-bar-update =
    fn (&loading-bar ratio)
        width = (sint (ratio * cols))
        col = ((&loading-bar 'width) + 1)
        while (col <= width)
            append
                &loading-bar 'elements
                rect
                    &loading-bar 'row
                    col
                    1
                    1
                    get-color 'loading ((float col) / cols)
            col += 1
        (&loading-bar 'width) = width
        
        (&loading-bar 'text) = (list)
        loading-bar-text-push &loading-bar ratio
        
        paint

### CONTENT ###


draw-flame =
    fn (&frame row start-col width)
        if ((width >= 1) and (row > 1))
            text = (&frame 'label)

            if (width > 1)
                if (((len text) > (width - 1)) and (width > 2))
                    text = (fmt "%.." (substr text 0 (width - 3)))
                text = (substr text 0 (width - 1))
            else
                text = ""

            add-element
                rect row start-col 1 width (&frame 'color)
                    'text       : text
                    'text-color : 0x000000

            &children = (&frame 'children)

            child-offset = 0
            foreach &label (&frame 'sorted-children-labels)
                &child = (&children &label)

                child-width = (sint (((float (&child 'count)) / (float (&frame 'count))) * width))
                if (child-width < 1) (child-width = 1)

                if ((child-offset + child-width) >= width)
                    child-width = (width - child-offset)

                if (child-width > 0)
                    draw-flame &child (row - 1) (start-col + child-offset) child-width

                child-offset += child-width
                unref &child

create-elements =
    fn ()
        elements := (list)

        if (flame-graph != nil)
            draw-flame flame-graph rows 1 cols

        add-element
            text 1 1 "press 'q' to quit"
        

### INPUT ###

flame-graph = nil

get-color =
    fn (type r)
        h = 0.0
        s = 0.5
        v = 0.75

        match type
            'loading
                h = 4.79966
                s = r
                v = 0.75
            'divider
                s = 0.0
                v = 0.5
            'kernel
                h = (0.15 * 3.14159)
            'cpp
                h = (0.25 * 3.14159)
            'python
                h = 0.0
                s = 0.25
            'gpu-symbol
                h = 3.14159
            'gpu-inst
                h = (0.6 * 3.14159)

        if (type != 'divider)
            v += (((float ((r % 1000) + 1)) / 1000.0) * 0.15)

        R = 0.0
        G = 0.0
        B = 0.0
        C = (v * s)
        X = (C * (1 - (abs (((h / (3.14159 / 3.0)) % 2.0) - 1))))
        m = (v - C)

        if ((h >= 0.0) and (h < (3.14159 / 3.0)))
            R = C
            G = X
            B = 0
        elif ((h >= (3.14159 / 3.0)) and (h < ((2.0 * 3.14159) / 3.0)))
            R = X
            G = C
            B = 0
        elif ((h >= ((2.0 * 3.14159) / 3.0)) and (h < 3.14159))
            R = 0
            G = C
            B = X
        elif ((h >= (3.14159 / 2.0)) and (h < ((4.0 * 3.14159) / 3.0)))
            R = 0
            G = X
            B = C
        elif ((h >= ((4.0 * 3.14159) / 3.0)) and (h < ((5.0 * 3.14159) / 3.0)))
            R = X
            G = 0
            B = C
        elif ((h >= ((5.0 * 3.14159) / 3.0)) and (h < (2.0 * 3.14159)))
            R = C
            G = 0
            B = X

        (((sint ((R + m) * 255)) & 255) << 16) |
            (((sint ((G + m) * 255)) & 255) << 8) |
                (sint ((B + m) * 255)) & 255

new-frame =
    fn (label)
        type = 'unknown

        if (startswith label "py::")
            type = 'python
        elif (contains label "::")
            type = 'cpp
        elif (endswith label "_[k]")
            type = 'kernel
            label = (substr label 0 ((len label) - 4))
        elif (endswith label "_[g]")
            type = 'gpu-inst
            label = (substr label 0 ((len label) - 4))
        elif (endswith label "_[G]")
            type = 'gpu-symbol
            label = (substr label 0 ((len label) - 4))
        elif (label == "-")
            type = 'divider

        object
            'label                  : label
            'type                   : type
            'color                  : (get-color type (rand))
            'count                  : 0
            'children               : (object)
            'sorted-children-labels : (list)

add-flame =
    fn (&frame &stack &count)
        if (len &stack)
            fname = (&stack 0)
            erase &stack 0

            &child = (&frame 'children)

            if (not (fname in &child))
                &child <- (fname : (new-frame fname))

            add-flame (&child fname) &stack &count

        (&frame 'count) += &count

get-sorted =
    fn (&frame)
        &children = (&frame 'children)
        if (len &children)
            sorted-children-labels = (list)

            foreach label &children
                &child = (&children label)
                get-sorted &child
                append sorted-children-labels (label : ((&children label) 'count))
                unref &child

            sorted-children-labels = (sorted sorted-children-labels (fn (a b) ((a 1) > (b 1))))

            foreach &pair sorted-children-labels
                append (&frame 'sorted-children-labels) (&pair 0)

parse-input =
    fn ()
        flame-graph := (new-frame "all")
        
        f = (fopen-rd ((argv) 1))
        lines = (fread-lines f)
        length = (len lines)
        
        add-element
            loading-bar 1 "PROFILE"
        &profile-bar = (newest-element)
        
        add-element
            loading-bar 2 "FLAME GRAPH"
        &flame-bar = (newest-element)
        
        loading-bar-update &profile-bar 0.0
        loading-bar-update &flame-bar 0.0
        
        strings = (object)
        stacks = (object)
        
        # What makes up a flame string, in order
        proc_name = ""
        pid = 0
        ustack = ""
        kstack = ""
        gpu_file = ""
        gpu_symbol = ""
        insn_text = ""
        stall_type = ""
        offset = 0x0
        flame_str = ""
        
        index = 0
        foreach &line lines
            split_line = (split &line "\t")
            event = (split_line 0)
            match event
                "string"
                    strings <- ((split_line 1) : (split_line 2))
                "proc_name"
                    proc_name = (strings (split_line 1))
                "pid"
                    pid = (split_line 1)
                "ustack"
                    ustack = (strings (split_line 1))
                "kstack"
                    kstack = (strings (split_line 1))
                "shader_type"
                    shader_type = (strings (split_line 1))
                "gpu_file"
                    gpu_file = (strings (split_line 1))
                "gpu_symbol"
                    gpu_symbol = (strings (split_line 1))
                "insn_text"
                    insn_text = (strings (split_line 1))
                "e"
                    stall_type = (strings (split_line 1))
                    offset = (split_line 2)
                    count = (parse-int (split_line 3))
                    flame_str =
                        fmt "%;%;%%-;%_[G];%_[G];%_[g];%_[g];0x%_[g];"
                            proc_name
                            pid
                            ustack
                            kstack
                            gpu_file
                            gpu_symbol
                            insn_text
                            stall_type
                            offset
                            
                    if (flame_str in stacks)
                        (stacks flame_str) += count
                    else
                        stacks <- (flame_str : count)
            if ((index % 10000) == 0)
                loading-bar-update &profile-bar ((float index) / length)
            index += 1
        loading-bar-update &profile-bar 1.0
        
        # Construct the flame graph from the stacks object
        index = 0
        length = (len stacks)
        foreach stack_str stacks
            stack = (split stack_str ";")
            count = (stacks stack_str)
            add-flame flame-graph stack count
            if ((index % 10) == 0)
                loading-bar-update &flame-bar ((float index) / length)
            index += 1
        loading-bar-update &flame-bar 1.0
            
        fclose f
        get-sorted flame-graph
        
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

redraw =
    fn (rows cols)
        rows := rows
        cols := cols
        create-elements
        paint

@on-init =
    fn (rows cols)
        redraw rows cols
        elements := (list)
        paint
        parse-input
        redraw rows cols

@on-resize =
    fn (rows cols)
        redraw rows cols
